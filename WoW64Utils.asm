format	COFF

; © Wolk-1024
; v29.02.2016

public	x64Call           as '_x64Call'
public	GetModuleHandle64 as '_GetModuleHandle64'
public	GetProcAddress64  as '_GetProcAddress64'
public	memcpy64          as '_memcpy64'
public	GetTeb64          as '_GetTeb64'
public	GetPeb64          as '_GetPeb64'
public	GetNtdll64        as '_GetNtdll64'

include '..\include\win32ax.inc'

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
      push   0x33
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

WIN64_SEGMENT	    = 0x33
WOW64_SEGMENT	    = 0x23
MAX_STACK_PARAM     = 0x100
IMAGE_NT_SIGNATURE  = 0x00004550
IMAGE_DOS_SIGNATURE = 0x5A4D

;--------------------------------------------------------;
;                        x64Call                         ;
;--------------------------------------------------------;
; [in]	pfnProc64 - Указатель на вызываемую функцию.	 ;
; [in]	nArgs	  - Количество передаваемых параметров.  ;
; [in]	...	  - Список параметров для функции.           ;
; [out] EDX:EAX   - Результат вызова.                    ;
;--------------------------------------------------------;

proc x64Call c uses ebx esi edi, pfnProc64:qword, nArgs:dword, ...:dword

     %jmp33                            ; Прыжок в 64-битный сегмент.
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
;                  GetModuleHandle64                     ;
;--------------------------------------------------------;
; [in]	lpProcName - Имя искомой библиотеки.             ;
; [out] EDX:EAX    - Адрес загрузки или 0.               ;
;--------------------------------------------------------;

proc GetModuleHandle64 c uses esi edi, lpProcName:dword

     %jmp33                            ;
     mov    rax, 0x60                  ;
     mov    rax, qword [gs:rax]        ; RAX = PEB64
     mov    rax, qword [rax+0x18]      ; RAX = PEB64->Ldr
     mov    rax, qword [rax+0x10]      ; RAX = PEB64->Ldr.InLoadOrderModuleList.Flink (Первый модуль)
     mov    rdx, rax                   ;
     cld                               ;
.NextModule:
     movzx  rcx, word  [rax+0x58]      ; RCX = LdrDataTableEntry.BaseDllName.Length
     mov    rsi, qword [rax+0x60]      ; RSI = LdrDataTableEntry.BaseDllName.Buffer
     mov    edi, [lpProcName]	       ;
     shr    rcx, 1                     ;
     repe   cmpsw                      ;
     je     .Found                     ;
     mov    rax, qword [rax]	       ; RAX = InLoadOrderModuleList[n].Flink (Следующий модуль)
     cmp    rdx, qword [rax]	       ; Проверяем не конец ли списка.
     jne    .NextModule                ;
     xor    eax, eax                   ;
     jmp    .Exit                      ;
.Found:
     mov    rax, qword [rax+0x30]      ; RAX = LdrDataTableEntry.DllBase
.Exit:
     mov    rdx, rax                   ;
     shr    rdx, 32                    ;
     %jmp23                            ;
     ret                               ;
endp

;--------------------------------------------------------;
;                   GetProcAddress64                     ;
;--------------------------------------------------------;
; [in]	hModule    - Адрес загрузки библиотеки. 	 ;
; [in]	lpProcName - Имя искомой функции или её ординал. ;
; [out] EDX:EAX    - Вернёт 0 или адрес.		 ;
;--------------------------------------------------------;

proc GetProcAddress64 c uses ebx esi edi, hModule:qword, lpProcName:dword

     %jmp33                            ;
     mov    rbx, qword [hModule]       ;
     mov    edx, dword [lpProcName]    ;
     cmp    word [rbx], 'MZ'	       ;
     jne    .Error                     ;
     mov    r11d, dword [rbx+0x3C]     ; ImageDosHeader->e_lfanew
     add    r11, rbx                   ;
     cmp    dword [r11], 'PE'	       ;
     jne    .Error                     ;
     mov    r11d, dword [r11+0x88]     ; ImageNtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
     test   r11d, r11d                 ;
     je     .Error                     ;
     add    r11, rbx                   ;
     mov    r10d, dword [r11+0x20]     ; ImageExportDirectory->AddressOfNames (RVA)
     add    r10, rbx                   ;
     mov    ecx,  dword [r11+0x18]     ; ImageExportDirectory->NumberOfNames
     test   edx, 0xffff0000            ; if (((DWORD)lpProcName & 0xffff0000) == 0)
     je     .Ordinal                   ;
     cld                               ;
.NextProc:
     dec    ecx                        ;
     jle    .Error                     ;
     mov    esi, dword [r10+rcx*4]     ; char* Name = (char*)(AddressOfNames[IndexName] + hModule);
     add    rsi, rbx                   ;
     mov    edi, edx                   ;
.Char:
     lodsb                             ;
     shl    eax, 8                     ;
     xchg   rdi, rsi                   ;
     lodsb                             ;
     test   ax, ax                     ;
     je     .Found                     ;
     cmp    al, ah                     ;
     je     .Char                      ;
     jmp    .NextProc                  ;
.Ordinal:
     mov    ecx, dword [r11+0x10]      ; ImageExportDirectory->Base
     mov    eax, dword [r11+0x14]      ; ImageExportDirectory->NumberOfFunctions
     add    eax, ecx                   ;
     cmp    edx, eax                   ;
     jae    .Error                     ;
     cmp    edx, ecx                   ;
     jl     .Error                     ;
     xchg   ecx, edx                   ; ecx = edx; edx = ecx
     sub    ecx, edx                   ; FunctionIndex = Ordinal - ExportDirectory->Base;
     jmp    @f                         ;
.Found:
     mov    eax, dword [r11+0x24]      ; ImageExportDirectory->AddressOfNameOrdinals (RVA)
     add    rax, rbx                   ;
     movzx  ecx, word  [rax+rcx*2]     ; FunctionIndex = AddressOfNameOrdinals[IndexName]
  @@:
     mov    eax, dword [r11+0x1C]      ; ImageExportDirectory->AddressOfFunctions (RVA)
     add    rax, rbx                   ;
     mov    eax, dword [rax+rcx*4]     ; AddressOfFunctions[FunctionIndex]
     add    rax, rbx                   ;
     jmp    .Exit                      ;
.Error:
     xor    eax, eax                   ;
.Exit:
     mov    rdx, rax                   ;
     shr    rdx, 32                    ;
     %jmp23                            ;
     ret                               ;
endp

;--------------------------------------------------------;
;                       memcpy64                         ;
;--------------------------------------------------------;
; [in]	Dest - Адрес буфера назначения. 	             ;
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
     cld                               ;
     shr    ecx, 3                     ;
     repe   movsq                      ;
     mov    ecx, edx		           ;
     and    ecx, 7                     ;
     repe   movsb                      ;
     %jmp23                            ;
     retf                              ;
endp

proc GetTeb64

     mov    edx, 0x30		           ; TEB64->NtTib.Self
     mov    eax, dword [gs:edx]        ;
     mov    edx, dword [gs:edx+4]      ;
     ret			                   ;

endp

proc GetPeb64

     mov    edx, 0x60		           ; TEB64->PEB64
     mov    eax, dword [gs:edx]        ;
     mov    edx, dword [gs:edx+4]      ;
     ret                               ;

endp

proc GetNtdll64

     mov    eax, 0x60                  ;
     mov    eax, dword [gs:eax]        ;
     mov    eax, dword [eax+0x18]      ;
     mov    eax, dword [eax+0x10]      ;
     mov    eax, dword [eax]	       ;
     mov    edx, dword [eax+0x30]      ;
     ret			                   ;

endp