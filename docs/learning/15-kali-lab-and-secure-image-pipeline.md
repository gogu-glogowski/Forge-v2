# Prompt 15: Kali-Lab i bezpieczny pipeline obrazu

## Cel

Prompt 15 dodał Kali-Lab jako pierwszego rzeczywiście nowego gościa spoza rodziny Fedora. Nie chodziło o skopiowanie istniejącej implementacji Fedora-Lab i zmianę kilku nazw. Celem było sprawdzenie, czy Generic Factory potrafi utworzyć persistent VM o innej polityce obrazu i provisioningu, korzystając nadal ze wspólnych mechanizmów planowania, storage, ownership, durable state, lifecycle oraz reconciliation.

Kali-Lab zostało opisane jako profil, a nie jako osobny lifecycle. Profile-specific pozostają źródło obrazu, metoda jego weryfikacji, firmware, zasoby oraz zasady pierwszego uruchomienia. Generic pipeline nadal odpowiada za identity instancji i generacji, przygotowanie storage, persistent domain, durable `Preparing`, publikację `Active` oraz późniejszy status i reconciliation.

## Kali jako pierwszy non-Fedora guest

Profil `kali-lab` definiuje:

- rodzinę gościa Kali i rodzaj instancji Lab,
- architekturę x86_64,
- BIOS z maszyną Q35,
- persistent managed lifecycle,
- sieć `DefaultNat` i wirtualną grafikę,
- provisioning `None`,
- first-boot policy `ManualGuest`,
- własne limity CPU, pamięci i dysku,
- oficjalne źródło oraz supply-chain policy Kali.

To rozdzielenie było istotnym dowodem Generic Factory. Kali korzysta z tych samych typed `InstanceName`, Generation ID, nazw zasobów, state layout, domain/storage planów i transakcji creation co pozostałe profile. Nie powstał osobny „kali-state”, osobny mechanizm reconciliation ani kopia wspólnego operational lifecycle.

## Oficjalny obraz Kali 2026.2

Źródłem jest oficjalne archiwum Kali Linux 2026.2 przygotowane dla QEMU na x86_64. Upstream publikuje gotowy qcow2 wewnątrz archiwum `.7z`, a nie Fedora Cloud qcow2 pobierany bezpośrednio.

Łańcuch zaufania wygląda następująco:

```text
przypięta identity oficjalnego klucza Kali
  → detached signature pliku SHA256SUMS
  → uwierzytelniony SHA-256 archiwum .7z
  → walidowana ekstrakcja dokładnie jednego qcow2
  → lokalny SHA-256 prepared qcow2
```

Forge wymaga detached signature, zgodności fingerprintu klucza z przypiętą wartością oraz dokładnej sumy SHA-256 archiwum. Nie istnieje ścieżka przejścia do trusted state przez `Unverified`, sam sukces pobrania ani sam exit code `7z`.

## Hardened listing i extraction

Przed ekstrakcją Forge wykonuje listing `7z l -slt` i waliduje jego structured output. Archiwum musi zawierać dokładnie jeden oczekiwany, płasko położony plik qcow2. Pipeline odmawia działania dla:

- `..` i innych form path traversal,
- ścieżek absolutnych Unix i Windows,
- nieoczekiwanego nested layout,
- symlinków,
- hardlinków,
- wpisów katalogowych udających oczekiwany plik,
- więcej niż jednego qcow2,
- braku qcow2.

Ekstrakcja odbywa się wyłącznie wewnątrz kontrolowanego przez Forge katalogu tymczasowego z prywatnymi permissions. Wynik jest sprawdzany przez `symlink_metadata`, canonical path, typ regular file i liczbę linków. Plik musi leżeć bezpośrednio wewnątrz oczekiwanego temp root. Cleanup katalogu tymczasowego jest ograniczony do zweryfikowanego dziecka katalogu downloads i nie może wyjść ponad ten root.

Po ekstrakcji Forge ponownie oblicza SHA-256 archiwum, oblicza SHA-256 qcow2 i dopiero wtedy może rozpocząć publikację prepared image. Sukces procesu `7z` jest więc tylko jednym z dowodów, a nie końcem weryfikacji.

## Pierwsza realna próba i pozornie przerwana promocja

Pierwszy zatwierdzony realny create nie zakończył się w sposób widoczny dla operatora. Oficjalne archiwum zostało poprawnie pobrane i zweryfikowane, a ekstrakcja zakończyła się sukcesem. Kontrolowany temp root zawierał qcow2 o pełnym rozmiarze. Finalny prepared path również pojawił się, lecz w pierwszym snapshotcie brakowało kompletnej metadata publikującej trusted state. Ten stan został początkowo sklasyfikowany jako przerwanie parenta podczas promocji. Późniejsze snapshoty obaliły tę diagnozę: proces nadal pracował w innym sandboxie i ostatecznie kontynuował kolejne etapy create.

Nie był to błąd `7z`. Niezależne `7z t` zwróciło `Everything is Ok`, listing zawierał dokładnie jeden oczekiwany regular file, a temp i final qcow2 miały pełny deklarowany rozmiar i identyczny SHA-256. Nie było również śladów OOM kill, I/O error, braku miejsca ani quota failure.

Wąskim gardłem była ówczesna promocja przez pełne kopiowanie rozpakowanego qcow2. Plik miał około 16 GB, więc redundantny zapis otworzył wielominutowe okno, w którym kolejne snapshoty widziały różne etapy tej samej nadal trwającej operacji. Była to również realna granica crash-consistency: rzeczywiste zakończenie procesu w tym miejscu pozostawiłoby final path bez opublikowanej metadatyki. Nie wolno było uznać istniejącego qcow2 za trusted tylko dlatego, że jego nazwa i rozmiar wyglądały poprawnie.

## Model stanu prepared image

Pipeline jawnie rozróżnia:

- `Missing` — nie ma rozpoczętego ani opublikowanego obrazu,
- `Preparing` — trwa przygotowanie opisane durable intent,
- `Verified` — prepared image ma kompletną metadatę i przechodzi świeżą exact validation,
- `InterruptedPreparation` — istnieją ślady rozpoczętego przygotowania, ale publikacja nie została ukończona,
- `OrphanedPreparedImage` — finalny qcow2 istnieje bez kompletnej, zgodnej metadatyki,
- `Conflict` — ślady lub identity są sprzeczne, uszkodzone albo niejednoznaczne.

Najważniejsza reguła brzmi:

```text
istniejący qcow2 bez zgodnej metadata != trusted prepared image
```

Normalny fetch nie adoptuje takiego pliku heurystycznie. Orphan lub konflikt wymaga jawnego recovery albo exact cleanupu przed czystym retry.

## Crash-safe publication

Pełne kopiowanie zastąpiono atomową promocją no-clobber opartą na hard linku w obrębie tego samego filesystemu:

```text
durable preparation intent
  → fsync extracted qcow2
  → exact no-clobber hard link do final path
  → fsync katalogu images
  → unlink temp entry
  → fsync katalogu temp
  → usunięcie temp root
  → fsync katalogu downloads
  → zapis metadata temp
  → fsync metadata
  → atomic metadata rename
  → fsync katalogu images
  → usunięcie intent
```

Źródło musi być pojedynczym regular file, destination musi być oczekiwaną ścieżką, a oba katalogi muszą znajdować się na tym samym filesystemie. Istniejący destination powoduje refusal; nie jest nadpisywany. Brak obsługi hard linku lub próba cross-filesystem również kończy się fail-closed zamiast powrotu do luźniejszej ścieżki.

Testy crash matrix obejmują przerwanie:

- przed final link,
- po final link, ale przed unlink temp,
- po unlink temp, ale przed metadata,
- po zapisie metadata temp, ale przed rename,
- po publikacji metadata.

Każdy stan jest rozpoznawalny po restarcie i żaden nie prowadzi do silent trust. Dopiero opublikowana metadata, exact paths, regular-file identity oraz świeże checksumy dają `Verified`.

## ManualGuest bez Fedora assumptions

Kali-Lab jest persistent `ManualGuest`. Creation success oznacza, że Forge:

- przygotował zweryfikowaną shared base,
- utworzył owned writable overlay,
- zapisał durable generation ownership,
- zdefiniował persistent BIOS/Q35 domain,
- ponownie sprawdził exact storage/domain identity,
- atomowo opublikował generację jako `Active`.

Kali pozostaje `shutoff` i jest gotowe do ręcznej obsługi przez Virt-Manager. Creation nie uruchamia domeny i nie wymaga:

- NoCloud seeda,
- cloud-init,
- użytkownika `forge`,
- SSH,
- QGA,
- DHCP ani guest-side hostname evidence.

Brak tych elementów nie oznacza zdegradowanego Fedora flow. Jest poprawnym wynikiem typed policy `ProvisioningPolicy::None` i `FirstBootSuccessPolicy::ManualGuest`.

## Accidental seed coupling w reconciliation

Po zakończeniu create durable generation była `Active`, domena była persistent i `shutoff`, a exact overlay wskazywał trusted Kali base. Mimo tego pierwsze `forge state reconcile kali-lab` zwróciło `Conflict` z powodu braku `NoCloudSeed`.

To był rzeczywisty błąd Forge: shared profile binding bezwarunkowo oczekiwał seeda, chociaż generic generation matcher potrafił już poprawnie porównywać generacje z dwoma lub trzema zasobami. Była to pozostałość Fedora-specific assumption w operational path.

Poprawka stała się policy-driven:

```text
NoCloud          → dokładnie jeden zgodny seed jest wymagany
None/ManualGuest → seed musi być nieobecny
```

Brak seeda dla NoCloud, seed o innej identity oraz jakikolwiek seed dla `None` powodują `Conflict`. Nie dodano gałęzi sprawdzającej literalne `kali-lab`. Fedora regression potwierdza, że Fedora-Lab nadal wymaga własnego exact seeda.

## Forge process supervision a błąd obserwatora

Historia procesu nie może zostać wygładzona. Po początkowym braku wyniku kolejny sandbox nie widział wcześniejszego procesu przez `pgrep`, więc operacja została przedwcześnie uznana za zakończoną. Późniejsze read-only snapshoty pokazywały jednak kolejne etapy: finalny obraz, metadane, base volume, overlay, state i w końcu persistent domain.

Review wykazał, że Forge poprawnie używa synchronicznego `Command::output()` dla `curl`, `gpg`, `gpgv` i `7z`. Metoda czeka na zakończenie child process i udostępnia jednoznaczny exit status. Generic create również nie raportuje sukcesu przed zakończeniem transakcji.

Błąd leżał po stronie zewnętrznego obserwatora: kolejne wywołania działały w odseparowanych sandboxach/process namespaces, a utrata widoczności procesu nie była terminalnym wynikiem pierwotnej sesji. Dlatego nie zmieniono supervision Forge bez dowodu lokalnego błędu. Operację wolno uznać za zakończoną tylko po terminalnym wyniku jej własnego execution handle, nigdy na podstawie `pgrep` z innego środowiska.

## Finalny stan

Po naprawie policy-driven reconciliation:

```text
Kali-Lab:
  persistent = true
  domain state = shutoff
  generation = Active
  observed generation = Active
  seed = none
  ManagedReconciliationStatus = Consistent

Fedora-Lab:
  ManagedReconciliationStatus = Consistent
```

Kali ma owned overlay z backing relationship do zweryfikowanej shared Kali base. Nie zostało automatycznie uruchomione. Nie wymaga QGA, SSH ani cloud-init do potwierdzenia poprawności creation. Fedora-Lab zachowała dotychczasowy NoCloud lifecycle i exact seed semantics.

## Najważniejsze lekcje

- Nowa dystrybucja powinna wnosić policy i adapter supply-chain, a nie kopię lifecycle.
- Podpis sum kontrolnych, pinned key identity i checksum archiwum tworzą jeden łańcuch zaufania; żadnego kroku nie można pominąć.
- Parser listingu archiwum jest granicą bezpieczeństwa, nie kosmetycznym sprawdzeniem nazwy.
- Sam sukces ekstraktora nie dowodzi bezpiecznego ani kompletnego wyniku.
- Prepared image potrzebuje crash-consistent publication i jednoznacznego stanu po każdym możliwym przerwaniu.
- Orphan nie jest automatycznie adoptowany.
- ManualGuest nie powinien dziedziczyć cloud-init, SSH, QGA ani seed assumptions z Fedora Cloud.
- Reconciliation musi wynikać z profilu, a nie z historii pierwszego zaimplementowanego gościa.
- Brak widoczności procesu z innego sandboxu nie jest exit statusem procesu.
