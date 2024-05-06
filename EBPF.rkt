#lang racket

(require redex)

(provide ebpf)


(define-language ebpf

  ;;Representação da palavra 
  (instr ::= (word ...))
  
  (word ::= (immediate offset sourceReg destinationReg opcode))
  
  (immediate ::= number)
  
  (offset ::= number ext)
  
  (sourceReg ::= registerCode)
  
  (destinationReg ::= registerCode)
  
  (opcode ::= (msb source lsb)
               eof)
  (msb ::=
        ;;Arithmetic Instructions
        ;;Math
         bpf-add bpf-sub bpf-mul bpf-div bpf-sdiv bpf-mod bpf-smod
         bpf-add32 bpf-sub32 bpf-mul32 bpf-div32 bpf-sdiv32 bpf-mod32 bpf-smod32
        ;;Boolean
         bpf-or bpf-and bpf-neg bpf-neg32 
        ;;Shift
         bpf-lsh bpf-lsh32 bpf-rsh bpf-rsh32 bpf-arsh bpf-arsh32 bpf-xor
        ;;Commands
         bpf-mov bpf-mov32 bpf-end
        ;;Jump Instructions
         bpf-ja
        ;;Commands
         bpf-call bpf-exit
        ;;Conditioned Jump
           bpf-jeq bpf-jeq32 bpf-jgt bpf-jgt32 bpf-jge bpf-jge32
           bpf-jset bpf-jset32 bpf-jne bpf-jne32 bpf-jsgt bpf-jsge
           bpf-jsgt32 bpf-jsge32 bpf-jlt bpf-jlt32
           bpf-jle bpf-jle32 bpf-jslt bpf-jsle bpf-jslt32 bpf-jsle32)
  
  (source ::= bpf-k bpf-x)
  
  (lsb ::= bpf-ld bpf-ldx bpf-st bpf-stx bpf-alu bpf-jmp bpf-jmp32 bpf-alu64)

  ;;Representação dos registradores
  (registers ::= (register ...))
  
  (register ::= (registerCode content)) ;;Representador do Registrador Generico
  
  (content ::= number)
  
  (registerCode ::= r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 rP);;Lista dos possiveis registradores
  
  ;;Representação de um Programa EBPF
  (pc ::= number);;Contador de Programa
  
  (program ::= (registers instr pc ))
  
  (symbol ::= equal greater less greater-eq less-eq greater-sig less-sig greater-eq-sig less-eq-sig bool-and diff)
  
 )
