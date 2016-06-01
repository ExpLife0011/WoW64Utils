format COFF

; © Wolk-1024
; v01.06.2016

public x64Call           as '_x64Call'
public GetModuleHandle64 as '_GetModuleHandle64'
public GetProcAddress64  as '_GetProcAddress64'
public memcpy64          as '_memcpy64'
public memcmp64          as '_memcmp64'
public GetTeb64          as '_GetTeb64'
public GetPeb64          as '_GetPeb64'
public GetNtdll64        as '_GetNtdll64'
public IsWoW64           as '_IsWoW64'

include '..\include\win32ax.inc'

macro %IsWoW64
{        
    xor    eax, eax             
    dec    eax 
    neg    eax  
}

macro retfq val
{
   if ~ val eq
     db 0xCA   ; retf val
     dw val
   else
     db 0xCB   ; retf
   end if
}

macro %jmp33 Address
{
   use32
   if ~ Address eq
      jmp    far 0x33:Address
   else
      push   0x33  ; Heavens Gate
      call   $ + 5
      add    dword [esp], 5
      retf
   end if
   use64
}

macro %jmp23 Address
{
   use64
   if ~ Address eq
     push   0x23
     push   Address
     retf
   else
     push   0x23
     call   $ + 5
     add    qword [rsp], 7
     retf
   end if
   use32
}

WIN32_SEGMENT = 0x1B
WOW64_SEGMENT = 0x23
WIN64_SEGMENT = 0x33
IMAGE_NT_SIGNATURE = 0x00004550   ; PE
IMAGE_DOS_SIGNATURE = 0x5A4D	  ; MZ
IMAGE_FILE_MACHINE_AMD64 = 0x8664

;--------------------------------------------------------;
;                        x64Call                         ;
;--------------------------------------------------------;
; [in]	pfnProc64 - Указатель на вызываемую функцию.	 ;
; [in]	nArgs	  - Количество передаваемых параметров.  ;
; [in]	...	  - Список параметров для функции.           ;
; [out] EDX:EAX   - Результат вызова.                    ;
;--------------------------------------------------------;

proc x64Call c uses ebx esi edi, pfnProc64:qword, nArgs:dword, ...:dword

     %jmp33                            ; Прыгаем в 64-битный сегмент.
     mov    ebx, esp                   ;
     mov    rax, qword [pfnProc64]     ; RAX = Вызываемая функция.
     mov    ecx, dword [nArgs]	       ; ECX = Количество передаваемых аргументов.
     lea    esi, dword [...]	       ; ESI = Адрес начала списка аргументов.
     lea    edx, [ecx*8]               ; EDX = Размер параметров.
     add    edx, 32                    ;
     and    edx, 0xE0                  ; Выравниваем размер параметров по 32 байтной границе.
     and    esp, 0xfffffff0            ; Win64 требует выравнивание стека на 16 байт
     sub    esp, edx                   ; Выделяем буфер для параметров.
     mov    edi, esp                   ; EDI = Указатель на буфер.
     cld                               ;
     repe   movsq                      ; Копируем параметры в буфер.
     mov    rcx, [rsp + 0 * 8]	       ; 1-й параметр.
     mov    rdx, [rsp + 1 * 8]	       ; 2-й
     mov    r8,  [rsp + 2 * 8]	       ; 3
     mov    r9,  [rsp + 3 * 8]	       ; 4
     movd   xmm0, ecx                  ;
     movd   xmm1, edx                  ;
     movd   xmm2, r8d                  ;
     movd   xmm3, r9d                  ;
     call   rax                        ; Вызываем функцию.
     mov    esp, ebx                   ;
     mov    rdx, rax                   ;
     shr    rdx, 32                    ;
     %jmp23                            ;
     ret                               ;

endp

;--------------------------------------------------------;
;                   GetModuleHandle64                    ;
;--------------------------------------------------------;
; [in]	ModuleName - Имя искомой библиотеки.             ;
; [out] EDX:EAX    - Адрес загрузки или 0.               ;
;--------------------------------------------------------;

proc GetModuleHandle64 c uses esi edi, ModuleName:dword

     %jmp33                            ;
     mov    rax, 0x60                  ;
     mov    rax, qword [gs:rax]        ; RAX = PEB64
     mov    rax, qword [rax+0x18]      ; RAX = PEB64->Ldr
     mov    rax, qword [rax+0x10]      ; RAX = PEB64->Ldr.InLoadOrderModuleList.Flink (Первый модуль)
     mov    rdx, rax                   ;
     cld                               ;
     mov    r8d, [ModuleName]	       ;
     test   r8d, r8d                   ;
     je     .Found                     ;
.NextModule:                           ;
     movzx  rcx, word  [rax+0x58]      ; RCX = LdrDataTableEntry.BaseDllName.Length
     mov    rsi, qword [rax+0x60]      ; RSI = LdrDataTableEntry.BaseDllName.Buffer
     mov    edi, r8d                   ;
     shr    ecx, 1                     ;
     repe   cmpsw                      ;
     je     .Found                     ;
     mov    rax, qword [rax]	       ; RAX = InLoadOrderModuleList[n].Flink (Следующий модуль)
     cmp    rdx, qword [rax]	       ; Проверяем не конец ли списка.
     jne    .NextModule                ;
     xor    eax, eax                   ;
     jmp    .Exit                      ;
.Found:                                ;
     mov    rax, qword [rax+0x30]      ; RAX = LdrDataTableEntry.DllBase
.Exit:                                 ;
     mov    rdx, rax                   ;
     shr    rdx, 32                    ;
     %jmp23                            ;
     ret                               ;

endp

;--------------------------------------------------------;
;                   GetProcAddress64                     ;
;--------------------------------------------------------;
; [in]	ModuleHandle  - Адрес загрузки библиотеки.       ;
; [in]	ProcedureName - Имя или ординал искомой функции. ;
; [out] EDX:EAX       - Вернёт 0 или адрес.              ;
;--------------------------------------------------------;

proc GetProcAddress64 c uses esi edi, ModuleHandle:qword, ProcedureName:dword

     %jmp33                            ;
     mov    rdx, qword [ModuleHandle]  ;
     test   rdx, rdx                   ;
     jle    .Error                     ;
     cmp    word [rdx], 'MZ'	       ; IMAGE_DOS_SIGNATURE
     jne    .Error                     ;
     mov    eax, dword [rdx+0x3C]      ; ImageDosHeader->e_lfanew
     add    rax, rdx                   ;
     cmp    dword [rax], 'PE'	       ; IMAGE_NT_SIGNATURE
     jne    .Error                     ;
     cmp    word [rax+0x04], 0x8664    ; IMAGE_FILE_MACHINE_AMD64
     mov    ecx, 0x88                  ;
     je     .Lib64                     ;
     sub    ecx, 0x10                  ;
.Lib64:                                ;
     mov    r8d, dword [rax+rcx]       ; ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
     test   r8d, r8d                   ;
     jle    .Error                     ;
     add    r8, rdx                    ;
     mov    r9d, dword [r8+0x20]       ; ImageExportDirectory->AddressOfNames (RVA)
     add    r9, rdx                    ;
     mov    ecx, dword [r8+0x18]       ; ImageExportDirectory->NumberOfNames
     mov    r10, rdx                   ;
     mov    edx, dword [ProcedureName] ;
     test   edx, 0xffff0000            ; if (((DWORD)lpProcName & 0xffff0000) == 0)
     je     .Ordinal                   ;
     cld                               ;
.NextProc:                             ;
     dec    ecx                        ;
     jle    .Error                     ;
     mov    esi, dword [r9+rcx*4]      ; char* Name = (char*)(AddressOfNames[IndexName] + hModule);
     add    rsi, r10                   ;
     mov    edi, edx                   ; edi = ProcedureName
.Char:                                 ;
     lodsb                             ;
     shl    eax, 8                     ;
     xchg   rdi, rsi                   ;
     lodsb                             ;
     test   ax, ax                     ; if ((Str1[i] == 0) && (Str2[i] == 0))
     je     .Found                     ;
     cmp    al, ah                     ;
     je     .Char                      ;
     jmp    .NextProc                  ;
.Ordinal:                              ;
     mov    ecx, dword [r8+0x10]       ; ImageExportDirectory->Base
     mov    eax, dword [r8+0x14]       ; ImageExportDirectory->NumberOfFunctions
     add    eax, ecx                   ;
     cmp    edx, eax                   ; if (Ordinal >= ExportDirectory->Base + ExportDirectory->NumberOfFunctions)
     jae    .Error                     ;
     cmp    edx, ecx                   ; if (Ordinal < ExportDirectory->Base)
     jl     .Error                     ;
     xchg   ecx, edx                   ;
     sub    ecx, edx                   ; FunctionIndex = Ordinal - ExportDirectory->Base;
     jmp    @f                         ;
.Found:                                ;
     mov    eax, dword [r8+0x24]       ; ImageExportDirectory->AddressOfNameOrdinals (RVA)
     add    rax, r10                   ;
     movzx  ecx, word  [rax+rcx*2]     ; FunctionIndex = AddressOfNameOrdinals[IndexName]
  @@:                                  ;
     mov    eax, dword [r8+0x1C]       ; ImageExportDirectory->AddressOfFunctions (RVA)
     add    rax, r10                   ;
     mov    eax, dword [rax+rcx*4]     ; AddressOfFunctions[FunctionIndex]
     add    rax, r10                   ;
     jmp    .Exit                      ;
.Error:                                ;
     xor    eax, eax                   ;
.Exit:                                 ;
     mov    rdx, rax                   ;
     shr    rdx, 32                    ;
     %jmp23                            ;
     ret                               ;

endp

;--------------------------------------------------------;
;                        memcpy64                        ;
;--------------------------------------------------------;
; [in]	Dest - Адрес буфера назначения.                  ;
; [in]	Src  - Адрес источника.                          ;
; [in]	Size - Длина данных.                             ;
; [out] Ничего.                                          ;
;--------------------------------------------------------;

proc memcpy64 c uses esi edi, Dest:qword, Src:qword, Size:dword

     %jmp33                            ;
     mov    rsi, [Src]		           ;
     mov    rdi, [Dest] 	           ;
     mov    ecx, [Size] 	           ;
     mov    edx, ecx		           ;
     test   ecx, ecx		           ;
     jle    .Exit		               ;
     cld			                   ;
     shr    ecx, 3		               ;
     repe   movsq		               ;
     mov    ecx, edx		           ;
     and    ecx, 7		               ;
     repe   movsb		               ;
.Exit:				                   ;
     %jmp23			                   ;
     ret			                   ;

endp

;--------------------------------------------------------;
;                       memcmp64                         ;
;--------------------------------------------------------;
; [in]	Ptr1 - Указатель на первый блок памяти.          ;
; [in]	Ptr2 - Указатель на второй блок памяти.          ;
; [in]	Size - Длина сравниваемых данных.                ;
; [out] EAX  - TRUE или FALSE                            ;
;--------------------------------------------------------;

proc memcmp64 c uses esi edi, Ptr1:qword, Ptr2:qword, Size:dword

     %jmp33                            ;
     mov    rsi, [Ptr1] 	           ;
     mov    rdi, [Ptr2] 	           ;
     mov    ecx, [Size]                ;
     mov    edx, ecx                   ;
     xor    eax, eax                   ;
     test   ecx, ecx                   ;
     jle    .Exit                      ;
     cld                               ;
     shr    ecx, 3                     ;
     repe   cmpsq                      ;
     jne    .Exit                      ;
     mov    ecx, edx                   ;
     and    ecx, 7                     ;
     repe   cmpsb                      ;
     sete   al                         ; Если ZF = 1, то eax = 1
.Exit:                                 ;
     %jmp23                            ;
     ret                               ;

endp

;--------------------------------------------------------;
;                        IsWoW64                         ;
;--------------------------------------------------------;
; [out] EAX - TRUE или FALSE                             ;
;--------------------------------------------------------;

proc IsWoW64

     xor   eax, eax                    ;
     mov   edx, cs                     ;
     cmp   edx, 0x23                   ; WOW64_SEGMENT
     sete  al                          ;
     ret                               ;

endp

;--------------------------------------------------------;
;                       GetTeb64                         ;
;--------------------------------------------------------;
; [out] EDX:EAX - 64-битный TEB.                         ;
;--------------------------------------------------------;

proc GetTeb64

     mov    edx, 0x30                  ; TEB64->NtTib.Self
     mov    eax, dword [gs:edx]        ;
     mov    edx, dword [gs:edx+0x04]   ;
     ret                               ;

endp

;--------------------------------------------------------;
;                       GetPeb64                         ;
;--------------------------------------------------------;
; [out] EDX:EAX - 64-битный PEB.                         ;
;--------------------------------------------------------;

proc GetPeb64

     mov    edx, 0x60                  ; TEB64->PEB64
     mov    eax, dword [gs:edx]        ;
     mov    edx, dword [gs:edx+0x04]   ;
     ret                               ;

endp

;--------------------------------------------------------;
;                      GetNtdll64                        ;
;--------------------------------------------------------;
; [out] EDX:EAX - Адрес загрузки 64-битной ntdll.dll	 ;
;--------------------------------------------------------;

proc GetNtdll64

     mov    eax, 0x60                  ;
     mov    eax, dword [gs:eax]        ;
     mov    eax, dword [eax+0x18]      ;
     mov    eax, dword [eax+0x10]      ;
     mov    edx, dword [eax]	       ;
     mov    eax, dword [edx+0x30]      ;
     mov    edx, dword [edx+0x34]      ;
     ret                               ;

endp