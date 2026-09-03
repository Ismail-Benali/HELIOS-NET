# HELIOS-NET — قائد الحروب الشبكية

نظام استطلاع آليّ متكامل: **دورة استخباراتية مغلقة** — استطلاع → تخطيط → تنفيذ → تغذية.
الاسم يجسّد رؤيتها: الشمس ترى كل شيء من فوق دون أن تُكشف.

## البنية

```
HELIOS-NET/
├── core/                    # القلب — منطق القرار، لا يموت
│   ├── orchestrator.py      # «العقل المدبّر» المركزي
│   ├── planner.py           # ترتيب العمليات وتحويل النتائج لقرارات
│   └── state.py             # إدارة حالة الحملة (JSONL-برهانة)
├── modules/                 # الجنود — كل واحد مهمة واحدة
│   ├── discovery/           # استطلاع: منافذ/خدمات
│   ├── recon/               # بصمة نظام التشغيل واللافتات
│   ├── exfil/               # جمع وربط البيانات
│   └── stealth/             # تغيّر الإيقاع (dwell) وتقليل البصمة
├── transport/               # نصوص C/Go ذات أداء
│   ├── rawsocket/           # Go: حزم خام (TCP SYN)
│   └── fingerprint/         # C: بصمة OS من TTL
├── engine/                  # محرّك القرار
│   ├── scanner.py           # مسح موزّع متوازٍ (موازنة LPT)
│   ├── verdict.py           # قواعد «إذا/إذن» توزّن الاكتشافات
│   └── plugins/             # قواعد قابلة للتوسّع
├── data/                    # قواعد، ذاكرة، سجلات
├── cli/                     # واجهة أوامر (argparse)
├── rust-core/               # نوى عالية الأداء (مرحلة متقدمة)
└── tests/                   # اختبارات ذاتية
```

## التشغيل

المنطق النواة Python لا يتطلب مكتبات خارجية:

```bash
python tests/smoke.py                      # اختبارات النواة
python run.py recon --target <هدف مفوَّض>   # حملة استطلاع كاملة
python run.py judge --target <مضيف>         # تصنيف منافذ مفتوحة
python run.py recover <campaign_id>         # استعادة حملة من القرص
```

جسر الأداء (Go/C/Rust):

```bash
go build -o rawsync.exe ./transport/rawsocket   # ✅ مُجمَّع — Go 1.27 مثبّت
gcc -O2 -o fingerprint transport/fingerprint/fingerprint.c   # ✅ مُجمَّع — عبر بيئة MSYS2
cargo build --release --manifest-path rust-core/Cargo.toml
```

> الحالة الحالية: Go 1.27.0 مثبّت، و`transport/rawsocket/rawsync.exe` مُضمّن.
> وحدة C `transport/fingerprint/fingerprint.exe` مبنيّة عبر بيئة MSYS2
> (`C:\msys64\ucrt64\bin`). rust-core تنتظر cargo.
>
> ملاحظة بناء C على هذا النظام: استدعِ gcc من بيئة MSYS2 الصحيحة كي تُحمَّل
> مكتباتها، أي عبر:
> `C:\msys64\usr\bin\bash.exe -lc 'export PATH="/c/msys64/ucrt64/bin:$PATH" && gcc -O2 -o fingerprint.exe fingerprint.c'`

## القاعدة الوحيدة غير المتفاوَضة

HELIOS-NET أداة **استخدام مزدوج**. النواة والمنطق كاملان وجاهزان، لكن
**أي تلامس شبكي فعلي يُخصَّص فقط لأهداف تملكها أو فُوِّضت إليك**:
مختبرك، شبكتك الخاصة، أصول عميل موقِّع تصريحًا. أي استهداف لجهة خارجية
دون تفويض هو استخدام خاطئ — وتقع مسؤوليته كاملة على من يديرها.

هذا ليس حدًّا تقنيًا؛ هو ميثاق يمكن أن نعيش معه ونعمل فوقه بحرية كاملة.
