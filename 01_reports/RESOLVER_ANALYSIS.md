═══════════════════════════════════════════════════════════════════════════════
  RESEARCH 2 — سیستم typeinfo و «resolve محلی» — تحلیل کامل (2026-09-27)
  ورودی: final_FULLIMAGE.bin (base 0x180000000) | ابزار: capstone خالص
  خروجی‌های خام: RESOLVER_DISASM.txt / DISASM2 / DISASM3 (کنار همین فایل)
═══════════════════════════════════════════════════════════════════════════════

■ نتیجه یک‌خطی
  «resolve محلی» به‌معنای واقعی وجود ندارد. مقاومت چیت در برابر افست صفر/خراب
  از دو مکانیزم می‌آید:
    1) COMMIT اتمی: پارسر تا وقتی هر ۱۶ کلید سالم resolve نشوند هیچ global ای
       را overwrite نمی‌کند.
    2) DEFAULT های کامپایل‌شده: مقادیر فعلی از قبل داخل .data هست.
  ⇒ با صفرها چیت کار کرد چون defaults با بیلد فعلی بازی می‌خوانند.
    روی بیلد جدید بازی، مود صفر می‌شکند (defaults کهنه می‌شوند).

■ اجزای سیستم (همه verify شده با دیساسمبلی)

  □ resolve_typeinfo  @ 0x18002c330
      ورودی: (rcx=engine_base? خیر: rcx=RVA, rdx, r8=name-string)
      ریشه خواندن: base = [0x1800D4388]  (بیس libunity — global مشترک)
      جریان:
        rva==0            → لاگ 'TypeInfo RVA unavailable' → return 0
        base invalid      → لاگ 'libunity base is invalid' → return 0
        slot = read24(base+rva)            ; اولین qword = TypeInfo ptr
        validate(slot, mode=1) → ok        → لاگ 'ok via direct TypeInfo'
        validate(slot, mode=0) → ok        → لاگ 'ok via direct TypeInfo static_fields'
        validate(*slot, 1)     → ok        → لاگ 'ok via legacy TypeInfo holder'
        هیچکدام نشد    → return 0 (پارسر فلگ fail را set می‌کند)
      نکته: بعد از fail، لاگ را برای 'ok' اسکن می‌کند (بایت 0x6F,0x6B) تا اگر
      قبلاً ok ثبت شده، خطای تکراری لاگ نکند.

  □ validator  @ 0x18002bb30   (امضای ساختار TypeInfo سفارشی بازی!)
      validate(ptr, mode, &out_ptr, &out_name):
        mode=1 (direct):        A = *(ptr+0x58)
        mode=0 (legacy holder): A = ptr
        سپس برای هر دو:  B = *(A+0x78) ; C = *B ; out_ptr = *(C+0x10)
        fail-reason ها (رشته‌ها): 'Il2CppClass invalid' / 'closed generic parent
        unresolved' / 'generic static_fields unresolved' / 'ConfigCollections
        Coll unresolved' / 'cached configs array unresolved'
      ⇒ ساختار TypeInfo سفارشی: TypeInfo+0x58=holder ، holder+0x78=block ،
        block+0x00=ptr ، ptr+0x10=Il2CppClass*. (هم‌خانواده RuntimeInfo+0xB8
        که قبلاً در entity_pawns.txt دیدیم — همون خانواده ساختارهاست.)

  □ پارسر + commit اتمی  @ ~0x18003f8f0..0x180041400
      هر کلید: مقدار hex string → عدد → resolve_typeinfo → نتیجه در ساختار
      محلی [rbp+0x00..0x70] (۱۶ قلم)
      فلگ fail (dil): اگر هر کلیدی fail شود set می‌شود
      commit @0x180041341: اگر dil==0 → کپی ۱۶ قلم به globals
        0x1800D2460..0x1800D2638 (typeinfo_engine تا typeinfo[14])
      اگر fail → هیچ write ای → defaults می‌مانند.

  □ default های کامپایل‌شده
      داخل کد hardcoded دیده می‌شوند (مثلاً @0x18001B1F5: cmp rcx,0xE8A5240 /
      cmp r14,0xE8AF0B0 / cmp r14,0xE8CA398) — مسیرهای generic config با
      مقایسه RVA فعال با default ها کار می‌کنند.
      (راستی‌آزمایی: 15/16 مقدار سرور == defaults؛ فقط character_model=0)

  □ مسیر generic ('ok via generic TypeInfo')
      ۴ سایت: 0x18002BD68 / 0x18002D0B5 / 0x18002D584 / 0x18002E4D8 —
      برای کلاس‌های generic (Weapon/Role/Item) با همان validator ولی مسیر
      mode=0 و مراحل اضافه generic.

■ نتیجه عملی برای سناریوی «بدون حساب»
  • امروز: مود --zero-offsets کار می‌کند (defaults درست‌اند) ✅
  • بیلد آینده بازی: defaults کهنه می‌شوند → دو راه:
      A) forward با کلید واقعی (vendor آپدیت می‌کند)
      B) ★ خودمان: RVA های جدید را پیدا کنیم (از طریق ساختار TypeInfo که الان
         فهمیدیم: هر اسلات = TypeInfo و walk +0x58→+0x78→+0x10 قابل صحت‌سنجی
         است — یعنی می‌توانیم اسکن کنیم کدام RVA های data پاس می‌کنند!) و
         سپس با WriteProcessMemory مستقیم globals 0x1800D2460.. را در حافظه
         DLL داخل MuMuNxDevice بنویسیم — بدون سرور، بدون پچ کد.
    راه B اکنون ممکن است چون فرمول صحت‌سنجی (validator walk) را می‌دانیم.

■ اتصال به تحقیق ۳ (scramble)
  ساختاری که typeinfo_decode.py دیروز خواند و «آشغال» به نظر رسید، همان
  TypeInfo سفارشی است — نه Il2CppClass استاندارد. پس غافلگیرکننده نیست:
  klass->name در +0x10 کلاس استاندارد است ولی ما روی TypeInfo سفارشی بودیم.
  walk صحیح: slot → TypeInfo → +0x58 → +0x78 → +0x00 → +0x10 = Il2CppClass
  → بعد klass+0x10 = name. (تست این walk = قدم بعدی session زنده)
═══════════════════════════════════════════════════════════════════════════════
