# qryx — Cryptography Security Graph

Інвентаризація і керування криптографією на рівні всієї організації: що, де і
яким алгоритмом шифрується, які з цих активів квантово-вразливі, і як їх
мігрувати. Open-core, dev-first, для mid-market.

> Sibling-продукт до [idryx](../Idryx) (Identity Security Graph). Спільна
> архітектурна ДНК: **X-BOM → граф → ризик → ремедіація**. idryx робить це для
> ідентичностей, qryx — для криптографії.

## Навіщо
NIST стандартизував постквантові алгоритми (2024); CNSA 2.0 ставить дедлайни
(нові системи 2027, legacy 2030, повна міграція 2035). «Harvest now, decrypt
later» робить дані, зашифровані вразливою крипто, скомпрометованими вже сьогодні.
Перший крок будь-якої міграції — discovery, а організації стабільно знаходять у
3-5x більше крипто-активів, ніж очікували. Готового mid-market / open-source
тулінгу для цього майже немає (усі гравці — enterprise-дорогі).

## Що робить
1. **Discovery** — сканує код, бінарі, TLS/мережу, сертифікати, key stores,
   cloud KMS, залежності; знаходить кожне використання криптографії.
2. **CBOM** — будує Cryptography Bill of Materials (CycloneDX) у єдиному графі.
3. **Ризик** — позначає квантово-вразливе (RSA/ECC), слабке (MD5/SHA-1/DES),
   misconfig, прострочені сертифікати, hardcoded ключі.
4. **Crypto-agility / ремедіація** — рекомендації переходу + PR у код/конфіг.

Деталі та дорожня карта — у [`qryx-plan.md`](./qryx-plan.md).

## Швидкий старт
```bash
make build
./bin/qryx scan <path>                 # людиночитний звіт
./bin/qryx scan --format cbom <path>   # CycloneDX 1.6 CBOM (JSON)
./bin/qryx scan --fail-on high <path>  # exit 2 якщо є finding >= high (для CI)
```

Приклад на вбудованих фікстурах:
```bash
make scan
```

## Що вже працює (Фаза 0)
CLI-сканер одного дерева, 5 детекторів:
- `cryptocall` — крипто-API в коді (Go / Python / JS / TS)
- `certfile` — парс PEM-сертифікатів (алгоритм, key size, expiry)
- `tlsconfig` — застарілі TLS/SSL у коді й nginx/apache-конфігах
- `hardcoded` — приватні ключі в коді/конфігах
- `deps` — крипто-бібліотеки в маніфестах залежностей

Класифікація ризику: `quantum-vulnerable` (RSA/ECC/DSA — Shor), `weak`
(MD5/SHA-1/DES/RC4, RSA<2048), `misconfig`, `expired`, `hardcoded`. PQC-алгоритми
(ML-KEM/ML-DSA, FIPS 203/204/205) розпізнаються як безпечні.

## Статус
Фаза 0 (MVP CLI-сканер) — робоча. Далі за [`qryx-plan.md`](./qryx-plan.md):
tree-sitter замість regex, CBOM-граф у Postgres, активний TLS-скан, cloud KMS.
