# Prompt 12: proven retained generation cleanup

## Cel

Prompt 12 doprowadził lifecycle managed generation do pierwszego realnego usunięcia zasobów należących do `Retained Owned Generation`. Cleanup nie wynikał z podobieństwa nazw plików ani z założenia, że starszy dysk jest już niepotrzebny. Podstawą były trwały ownership zapisany przez Forge oraz świeżo odczytany stan libvirt.

Celem nie było stworzenie ogólnego mechanizmu kasowania wszystkiego, co wygląda na stare. Chodziło o bezpieczne usunięcie dokładnie dwóch disposable resources generacji A — seeda i writable overlay — przy zachowaniu aktywnej generacji C, generacji B ze statusem `Failed`, wspólnej bazy oraz zasobów legacy.

## Główna zasada: prove before delete

Najkrótsze podsumowanie tego etapu brzmi:

```text
prove before delete
```

Sam manifest ownership nie wystarcza, ponieważ infrastruktura mogła zmienić się od chwili jego zapisania. Sam aktualny inventory libvirt również nie wystarcza, ponieważ obecność volume nie dowodzi, że Forge ma prawo nim zarządzać. Dopiero trzy elementy rozpatrywane razem pozwalają wykonać destrukcyjną operację:

```text
ownership manifest + reconciliation + absence of references
```

Forge musi wiedzieć, że sam utworzył zasób, potwierdzić zgodność durable state z aktualnym libvirt source of truth oraz udowodnić, że żadna domena ani inny volume nie korzysta z zasobu przeznaczonego do usunięcia.

## Stan przed cleanupem

Punktem wejścia był zakończony lifecycle Prompt 11:

```text
A = Retained
B = Failed
C = Active
active_generation_id = C
observed libvirt generation = C
ManagedReconciliationStatus = Consistent
```

A była jedyną generacją `Retained Owned`, dlatego tylko jej disposable resources mogły wejść do delete candidates. B nie kwalifikowała się dlatego, że `Failed` nie oznacza zgody na cleanup. C była aktywna i chroniona. Zasoby legacy bez durable ownership pozostawały `Unmanaged`, a shared Fedora base był `Shared / Protected`.

## Pre-execution revalidation

Cleanup plan identyfikował zasoby A przez Generation ID i immutable manifest, a następnie porównywał zapisane identity z aktualnym libvirt state. Sprawdzenie obejmowało:

- dokładny domain UUID,
- storage pool UUID,
- volume key i canonical path,
- format volume,
- capacity,
- backing relationship overlay do shared base,
- brak referencji z bieżącej domeny,
- brak referencji ze wszystkich pozostałych domen,
- brak użycia overlay A jako backing przez jakikolwiek inny volume.

Active C była chroniona zarówno przez status i `active_generation_id`, jak i przez aktualne referencje domeny do jej własnego overlay i seeda. SharedBase nie była disposable resource generacji A: występowała w manifeście jako chroniona zależność i nigdy nie trafiała do delete set.

Realna ścieżka korzystała z tego samego typed planu co dry-run. Bezpośrednio przed pierwszą mutacją odczytywała kompletny snapshot ponownie. Zmiana state lub libvirt pomiędzy planem a execute oznaczała odmowę przed delete, zamiast prób dopasowania nowej sytuacji heurystyką.

## Pierwsza próba: fail-closed timeout libvirt/D-Bus

Pierwsza próba wykonania Prompt 12A nie dotarła do delete. Typed reconciliation trafiło na timeout usługi libvirt/D-Bus. Późniejszy pojedynczy odczyt potrafił się udać, ale następny wymagany typed odczyt ponownie zakończył się timeoutem.

Nie był to dowód, że plan cleanupu jest błędny ani że zasoby A są niepoprawne. Był to brak kompletnego, świeżego snapshotu wymaganego do autoryzacji destrukcyjnej operacji. Zadziałała więc właściwa reguła:

```text
brak kompletnego fresh snapshotu → zero delete
```

Forge zatrzymał się przed zapisaniem cleanup intent i przed usunięciem pierwszego volume. Nie restartowano `virtqemud` ani polkit, nie zmieniano konfiguracji i nie stosowano workaroundu. Timeout nie został wygładzony ani zastąpiony starszym wynikiem. To było poprawne działanie zabezpieczenia fail-closed.

## Fresh retry

Przed ponowieniem operator wykonał ręczną, read-only kontrolę libvirt, która potwierdziła działający runtime, domenę `running`, jej trwałość i oczekiwany UUID. Te wyniki pomogły sklasyfikować wcześniejszy problem, ale nie zastąpiły wymaganej typed revalidation Forge.

Retry rozpoczął discovery od początku. Ponownie odczytano durable index i manifest A, a następnie świeżo wykonano:

- managed reconciliation,
- typed status domeny i storage,
- cleanup dry-run z exact identity i analizą referencji,
- revalidation wewnątrz realnej ścieżki execute.

Dopiero kompletny i stabilny snapshot, `Consistent`, observed C oraz brak konfliktów pozwoliły przejść do jawnego potwierdzenia realnego cleanupu.

## Realny cleanup

Po revalidation Forge wykonał dokładnie tę sekwencję:

```text
cleanup intent
  → exact seed delete
  → verify seed absence
  → persist progress
  → exact overlay delete
  → verify overlay absence
  → A = Cleaned
  → final reconciliation
```

Intent i postęp były zapisywane crash-safe. Delete korzystał z libvirt storage API i dokładnej identity volume. Nie używał `rm`, `sudo`, wildcardów ani `virsh vol-delete` jako backendu. Status `Cleaned` został opublikowany dopiero po potwierdzeniu, że oba disposable resources A nie istnieją.

Immutable manifest A pozostał historycznym rekordem tego, jakie zasoby należały do generacji. Bieżący lifecycle status A znajduje się w indeksie; manifest nie został przepisany po cleanupie.

## Dlaczego seed przed overlay

Przyjęta kolejność to:

```text
seed → overlay
```

NoCloud seed jest niezależnym disposable resource i nie uczestniczy w backing chain. Overlay wskazuje natomiast chronioną shared base. Usunięcie prostszego, niezależnego zasobu jako pierwszego ogranicza blast radius pierwszej mutacji i pozostawia bardziej strukturalny element do drugiego, ponownie kontrolowanego kroku.

Ta kolejność nie zmienia ochrony referencji: przed pierwszym delete oba zasoby muszą przejść pełną walidację, a po każdym delete Forge weryfikuje dokładną nieobecność usuniętego volume.

## Model partial failure

Cleanup storage nie jest transakcją, którą można uczciwie cofnąć. Po usunięciu volume Forge nie może „zrollbackować” operacji przez magiczne odtworzenie jego zawartości.

Model dlatego zapisuje durable cleanup intent i dokładny progress. Jeśli seed zostanie usunięty, ale delete overlay zawiedzie, Forge:

- nie odtwarza seeda,
- nie udaje pełnej atomowości,
- zapisuje stan częściowego lub niekompletnego cleanupu,
- zatrzymuje się po pierwszym błędzie,
- nie usuwa kolejnych zasobów,
- nie oznacza generacji jako `Cleaned`.

W realnym cleanupie A oba deletes zakończyły się sukcesem, więc ścieżka partial failure nie została uruchomiona na hoście. Chronią ją jednak testy regresyjne: sukces pierwszego delete i błąd drugiego muszą pozostawić drugi zasób, zachować jednoznaczny durable progress i nie wykonać żadnych dalszych deletes.

Ponowne uruchomienie cleanupu dla generacji już `Cleaned` zwraca typed `AlreadyCleaned` i wykonuje zero mutacji. Brak pojedynczego zasobu po przerwanym cleanupie jest akceptowany tylko wtedy, gdy istnieje odpowiadający mu durable state evidence — Forge nie zgaduje na podstawie samej nieobecności.

## Finalny rezultat

Po realnym cleanupie i końcowej walidacji stan wyglądał tak:

```text
A = Cleaned
B = Failed
C = Active
active_generation_id = C
observed libvirt generation = C
ManagedReconciliationStatus = Consistent
```

Inventory potwierdził:

- overlay A jest nieobecny,
- seed A jest nieobecny,
- overlay i seed C są obecne i pozostają aktywne,
- shared Fedora base jest obecny i chroniony,
- oba unmanaged legacy resources nadal istnieją i pozostają `Unmanaged`,
- delete candidates po operacji: `none`.

Generacja B pozostała `Failed`; cleanup A nie rozszerzył się na jej zasoby ani nie zmienił jej polityki lifecycle.

## Najważniejsze lekcje bezpieczeństwa

- Nie wykonujemy delete na podstawie nazwy, prefixu ani podobieństwa ścieżki.
- Każdy delete wymaga exact libvirt identity zgodnej z immutable ownership manifest.
- Revalidation bezpośrednio przed mutacją zamyka okno TOCTOU; drift oznacza refusal.
- Timeout lub niekompletny odczyt oznacza fail closed i zero delete.
- `Active`, `Preparing` i `Failed` nie są cleanup candidates.
- `SharedBase` jest zawsze chroniony.
- `Unmanaged legacy` pozostaje poza automatycznym cleanupem.
- Nie używamy `rm`, `sudo`, wildcardów ani shellowego prefix matching.
- `virsh` nie jest backendem delete; mutacja przechodzi przez typed libvirt storage API.
- Nie obiecujemy rollbacku dla nieodwracalnego usunięcia volume.

## Najważniejsze testy regresyjne

Testy Prompt 12 obejmują co najmniej:

- eligibility wyłącznie `Retained Owned`,
- odmowę dla `Active`, `Preparing` i `Failed`,
- ochronę `SharedBase` i `Unmanaged`,
- mismatch pool UUID,
- mismatch volume key i path,
- mismatch formatu, capacity i backing,
- cross-domain references,
- backing references z innych volumes,
- TOCTOU pomiędzy planem a execute z odmową przed delete,
- partial failure po pierwszym successful delete,
- sukces seed → overlay i przejście do `Cleaned`,
- typed `AlreadyCleaned` z zero mutation,
- zachowanie aktywnej generacji, shared base i zasobów legacy.

## Pełny lifecycle po Prompt 12

Forge realizuje teraz pełny lifecycle owned generation:

```text
create → own → activate → retain → prove → delete → Cleaned
```

Każda strzałka ma trwałą granicę i własne invariants. Szczególnie `prove` nie jest kosmetycznym dry-runem: to połączenie durable ownership, jednoznacznego reconciliation, exact identity i dowodu braku referencji, wykonywane ponownie tuż przed destrukcyjną zmianą.

## Czego nadal nie ma

Po Prompt 12 nadal nie istnieją:

- osobna polityka cleanupu zasobów generacji `Failed`,
- adoption zasobów legacy,
- ogólny SSH Host CA,
- Luna/Codex,
- YOLO mode,
- GUI.

Prompt 12 nie zmienił tych granic i nie rozszerzył cleanupu poza udowodnione `Retained Owned Generation`.
