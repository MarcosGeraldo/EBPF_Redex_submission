#lang racket
 
(require redex parser-tools/yacc  "lexer.rkt")
 
(define myparser
  (parser
 
   (start input)
   (end EOF)
   (tokens value-tokens op-tokens )
   (src-pos)
   (error (lambda (a b c d e) (begin (printf "a = ~a\nb = ~a\nc = ~a\nd = ~a\ne = ~a\n" a b c d e) (void))))   
   
   (grammar

    (input [() '()]           
           [(input line) (append $1  $2)])

    (line [(NEWLINE) '()]
          [(TRASH) '() ]
          [(ASM) '() ]
          [(exp) '()]
          [(HEX) (list  $1)]
          [(RESULT) '()]
          )
 
  (exp    




          [(ADD REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-add bpf-x bpf-alu))]
          [(ADD32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-add bpf-x bpf-alu))]
          [(ADD REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-add bpf-k bpf-alu))]
          [(ADD32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-add bpf-k bpf-alu))]

          [(SUB REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-sub bpf-x bpf-alu))]
          [(SUB32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-sub32 bpf-x bpf-alu))]
          [(SUB REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-sub bpf-k bpf-alu))]
          [(SUB32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-sub32 bpf-k bpf-alu))]

          [(MUL REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mul bpf-x bpf-alu))]
          [(MUL32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mul bpf-x bpf-alu))]
          [(MUL REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mul bpf-k bpf-alu))]
          [(MUL32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mul bpf-k bpf-alu))]

          [(DIV REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-div bpf-x bpf-alu))]
          [(DIV32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-div32 bpf-x bpf-alu))]
          [(DIV REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-div bpf-k bpf-alu))]
          [(DIV32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-div32 bpf-k bpf-alu))]

          [(SDIV REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-sdiv bpf-x bpf-alu))]
          [(SDIV32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-sdiv32 bpf-x bpf-alu))]
          [(SDIV REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-sdiv bpf-k bpf-alu))]
          [(SDIV32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-sdiv32 bpf-k bpf-alu))]

          [(MOD REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mod bpf-x bpf-alu))]
          [(MOD32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mod32 bpf-x bpf-alu))]
          [(MOD REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mod bpf-k bpf-alu))]
          [(MOD32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mod32 bpf-k bpf-alu))]
          [(MOD REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mod bpf-k bpf-alu))]
          [(MOD32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mod32 bpf-k bpf-alu))]

          [(SMOD REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-smod bpf-x bpf-alu))]
          [(SMOD32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-smod32 bpf-x bpf-alu))]
          [(SMOD REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-smod bpf-k bpf-alu))]
          [(SMOD32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-smod32 bpf-k bpf-alu))]
          [(SMOD REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-smod bpf-k bpf-alu))]
          [(SMOD32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-smod32 bpf-k bpf-alu))]
          
          [(NEG REG NUMBER) (list 0 0 'r0 (string->symbol (format "r~s" $3)) '(bpf-neg bpf-x bpf-alu))]
          [(NEG32 REG NUMBER ) (list 0 0 'r0 (string->symbol (format "r~s" $3)) '(bpf-neg32 bpf-x bpf-alu))]
         
          [(MOV REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mov bpf-x bpf-alu))]
          [(MOV32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-mov32 bpf-x bpf-alu))]
          [(MOV REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mov bpf-k bpf-alu))]
          [(MOV32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mov32 bpf-k bpf-alu))]
          [(MOV REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mov bpf-k bpf-alu))]
          [(MOV32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-mov32 bpf-k bpf-alu))]

          [(LSH REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-lsh bpf-x bpf-alu))]
          [(LSH32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-lsh32 bpf-x bpf-alu))]
          [(LSH REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-lsh bpf-k bpf-alu))]
          [(LSH32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-lsh32 bpf-k bpf-alu))]

          [(ARSH REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-arsh bpf-x bpf-alu))]
          [(ARSH32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-arsh32 bpf-x bpf-alu))]
          [(ARSH REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-arsh bpf-k bpf-alu))]
          [(ARSH32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-arsh32 bpf-k bpf-alu))]

          [(RSH REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-rsh bpf-x bpf-alu))]
          [(RSH32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-rsh32 bpf-x bpf-alu))]
          [(RSH REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-rsh bpf-k bpf-alu))]
          [(RSH32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-rsh32 bpf-k bpf-alu))]

          [(OR REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-or bpf-x bpf-alu))]
          [(OR32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-or bpf-x bpf-alu))]
          [(OR REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-or bpf-k bpf-alu))]
          [(OR32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-or bpf-k bpf-alu))]
          [(OR REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-or bpf-k bpf-alu))]
          [(OR32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-or bpf-k bpf-alu))]

          [(AND REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-and bpf-x bpf-alu))]
          [(AND32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-and bpf-x bpf-alu))]
          [(AND REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-and bpf-k bpf-alu))]
          [(AND32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-and bpf-k bpf-alu))]
          [(AND REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-and bpf-k bpf-alu))]
          [(AND32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-and bpf-k bpf-alu))]

          [(XOR REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-xor bpf-x bpf-alu))]
          [(XOR32 REG NUMBER SEP REG NUMBER) (list 0 0 (string->symbol (format "r~a" $6)) (string->symbol (format "r~s" $3)) '(bpf-xor bpf-x bpf-alu))]
          [(XOR REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-xor bpf-k bpf-alu))]
          [(XOR32 REG NUMBER SEP NUMBER) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-xor bpf-k bpf-alu))]
          [(XOR REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-xor bpf-k bpf-alu))]
          [(XOR32 REG NUMBER SEP HEX) (list $5 0 'r0 (string->symbol (format "r~a" $3)) '(bpf-xor bpf-k bpf-alu))]

          [(JNE REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne bpf-k bpf-jmp))]
          [(JNE REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jne bpf-x bpf-jmp))]
          [(JNE REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne bpf-k bpf-jmp))]
          [(JNE REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne bpf-k bpf-jmp))]
          [(JNE REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jne bpf-x bpf-jmp))]
          [(JNE REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne bpf-k bpf-jmp))]
          [(JNE32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-k bpf-jmp))]
          [(JNE32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-x bpf-jmp))]
          [(JNE32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-k bpf-jmp))]
          [(JNE32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-k bpf-jmp))]
          [(JNE32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-x bpf-jmp))]
          [(JNE32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne32 bpf-k bpf-jmp))]

          [(JEQ REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-k bpf-jmp))]
          [(JEQ REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-x bpf-jmp))]
          [(JEQ REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-k bpf-jmp))]
          [(JEQ REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-k bpf-jmp))]
          [(JEQ REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-x bpf-jmp))]
          [(JEQ REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq bpf-k bpf-jmp))]
          [(JEQ32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-k bpf-jmp))]
          [(JEQ32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-x bpf-jmp))]
          [(JEQ32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-k bpf-jmp))]
          [(JEQ32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-k bpf-jmp))]
          [(JEQ32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-x bpf-jmp))]
          [(JEQ32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jeq32 bpf-k bpf-jmp))]

          
          [(JGE REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jge bpf-x bpf-jmp))]
          [(JGE REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jge bpf-x bpf-jmp))]
          [(JGE REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jge bpf-x bpf-jmp))]
          [(JGE32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]
          [(JGE32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jge bpf-x bpf-jmp))]
          [(JGE32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jge bpf-k bpf-jmp))]

          [(JGT REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-k bpf-jmp))]
          [(JGT REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-x bpf-jmp))]
          [(JGT REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-k bpf-jmp))]
          [(JGT REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-k bpf-jmp))]
          [(JGT REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-x bpf-jmp))]
          [(JGT REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt bpf-k bpf-jmp))]
          [(JGT32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-k bpf-jmp))]
          [(JGT32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-x bpf-jmp))]
          [(JGT32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-k bpf-jmp))]
          [(JGT32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-k bpf-jmp))]
          [(JGT32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-x bpf-jmp))]
          [(JGT32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jgt32 bpf-k bpf-jmp))]

          [(JLE REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle bpf-k bpf-jmp))]
          [(JLE REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jle bpf-x bpf-jmp))]
          [(JLE REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle bpf-k bpf-jmp))]
          [(JLE REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jne bpf-k bpf-jmp))]
          [(JLE REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jle bpf-x bpf-jmp))]
          [(JLE REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle bpf-k bpf-jmp))]
          [(JLE32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-k bpf-jmp))]
          [(JLE32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-x bpf-jmp))]
          [(JLE32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-k bpf-jmp))]
          [(JLE32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-k bpf-jmp))]
          [(JLE32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-x bpf-jmp))]
          [(JLE32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jle32 bpf-k bpf-jmp))]

          [(JLT REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-k bpf-jmp))]
          [(JLT REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-x bpf-jmp))]
          [(JLT REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-k bpf-jmp))]
          [(JLT REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-k bpf-jmp))]
          [(JLT REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-x bpf-jmp))]
          [(JLT REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt bpf-k bpf-jmp))]
          [(JLT32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-k bpf-jmp))]
          [(JLT32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-x bpf-jmp))]
          [(JLT32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-k bpf-jmp))]
          [(JLT32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-k bpf-jmp))]
          [(JLT32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-x bpf-jmp))]
          [(JLT32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jlt32 bpf-k bpf-jmp))]

          [(JSLE REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-k bpf-jmp))]
          [(JSLE REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-x bpf-jmp))]
          [(JSLE REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-k bpf-jmp))]
          [(JSLE REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-k bpf-jmp))]
          [(JSLE REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-x bpf-jmp))]
          [(JSLE REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle bpf-k bpf-jmp))]
          [(JSLE32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-k bpf-jmp))]
          [(JSLE32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-x bpf-jmp))]
          [(JSLE32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-k bpf-jmp))]
          [(JSLE32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-k bpf-jmp))]
          [(JSLE32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-x bpf-jmp))]
          [(JSLE32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsle32 bpf-k bpf-jmp))]

          [(JSLT REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-k bpf-jmp))]
          [(JSLT REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-x bpf-jmp))]
          [(JSLT REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-k bpf-jmp))]
          [(JSLT REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-k bpf-jmp))]
          [(JSLT REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-x bpf-jmp))]
          [(JSLT REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt bpf-k bpf-jmp))]
          [(JSLT32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-k bpf-jmp))]
          [(JSLT32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-x bpf-jmp))]
          [(JSLT32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-k bpf-jmp))]
          [(JSLT32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-k bpf-jmp))]
          [(JSLT32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-x bpf-jmp))]
          [(JSLT32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jslt32 bpf-k bpf-jmp))]

          [(JSGT REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-k bpf-jmp))]
          [(JSGT REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-x bpf-jmp))]
          [(JSGT REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-k bpf-jmp))]
          [(JSGT REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-k bpf-jmp))]
          [(JSGT REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-x bpf-jmp))]
          [(JSGT REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt bpf-k bpf-jmp))]
          [(JSGT32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-k bpf-jmp))]
          [(JSGT32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-x bpf-jmp))]
          [(JSGT32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-k bpf-jmp))]
          [(JSGT32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-k bpf-jmp))]
          [(JSGT32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-x bpf-jmp))]
          [(JSGT32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsgt32 bpf-k bpf-jmp))]

          [(JSGE REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-k bpf-jmp))]
          [(JSGE REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-x bpf-jmp))]
          [(JSGE REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-k bpf-jmp))]
          [(JSGE REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-k bpf-jmp))]
          [(JSGE REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-x bpf-jmp))]
          [(JSGE REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge bpf-k bpf-jmp))]
          [(JSGE32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-k bpf-jmp))]
          [(JSGE32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-x bpf-jmp))]
          [(JSGE32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-k bpf-jmp))]
          [(JSGE32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-k bpf-jmp))]
          [(JSGE32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-x bpf-jmp))]
          [(JSGE32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jsge32 bpf-k bpf-jmp))]

          [(JSET REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset bpf-k bpf-jmp))]
          [(JSET REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jset bpf-x bpf-jmp))]
          [(JSET REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset bpf-k bpf-jmp))]
          [(JSET REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset bpf-k bpf-jmp))]
          [(JSET REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jset bpf-x bpf-jmp))]
          [(JSET REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset bpf-k bpf-jmp))]
          [(JSET32 REG NUMBER SEP NUMBER SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-k bpf-jmp))]
          [(JSET32 REG NUMBER SEP REG NUMBER SEP EXIT) (list 0 'ext (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-x bpf-jmp))]
          [(JSET32 REG NUMBER SEP HEX SEP EXIT) (list $5 'ext 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-k bpf-jmp))]
          [(JSET32 REG NUMBER SEP NUMBER SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-k bpf-jmp))]
          [(JSET32 REG NUMBER SEP REG NUMBER SEP NUMBER) (list 0 $8 (string->symbol (format "r~a" $6)) (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-x bpf-jmp))]
          [(JSET32 REG NUMBER SEP HEX SEP NUMBER) (list $5 $7 'r0 (string->symbol (format "r~a" $3)) '(bpf-jset32 bpf-k bpf-jmp))]



          [(EXIT) (list 0 0 'r0 'r0 '(bpf-exit bpf-x bpf-jmp))]
          ))))
             
(define (parseR ip)
  (port-count-lines! ip)  
  (myparser (lambda () (next-token ip))))   
 
(provide parseR)