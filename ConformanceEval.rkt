#lang racket


(require redex
         "Lexer/parserR.rkt"
         "EBPFReductions.rkt"
         "Lexer/parser.rkt")

(provide execFiles)

(define regs(term(((r0 0) (r1 0) (r2 0) (r3 0) (r4 0) (r5 0) (r6 0) (r7 0) (r8 0) (r9 0) (rP 0)))))

(define (parseCode code);Recebe os testes de conformidade e Retorna apenas o codigo
  (parse code)
  )

(define (parseResult code);Recebe os testes de conformidade e Retorna apenas o resultado
  (list-ref (parseR code) 0)
  )

(define (getResult code);Recebe a ultima execução das reduçoes e Retorna o resultado da execução das reduçoes
  (string->number
   (string-replace
    (string-replace
     (string-replace
      (list-ref
       (string-split (~v code) "(" #:repeat? #t) 1) ")" "")"r0" "")" " ""))
  )

(define (exe program);Recebe os testes de conformidade e Retorna a ultima redução obtida
  (apply-reduction-relation* ->exe (append regs (list (parseCode program)) (list 0)))
  )

(define (fileCompare program)
    (equal? (parseResult (open-input-file program)) (getResult (exe (open-input-file program)))) 
)

(define fileInput(term(
              "conformance_tests/add.data"
              "conformance_tests/add64.data"
              "conformance_tests/alu-arith.data" 
              "conformance_tests/alu-bit.data"   
              "conformance_tests/alu64-arith.data" 
              "conformance_tests/alu64-bit.data" 
              "conformance_tests/arsh32-imm-high.data"
              "conformance_tests/arsh32-imm-neg.data"
              "conformance_tests/arsh32-imm.data"
              "conformance_tests/arsh32-reg-high.data"
              "conformance_tests/arsh32-reg-neg.data"
              "conformance_tests/arsh32-reg.data"
              "conformance_tests/arsh64-imm-high.data"
              "conformance_tests/arsh64-imm-neg.data"
              "conformance_tests/arsh64-imm.data"
              "conformance_tests/arsh64-reg-high.data"
              "conformance_tests/arsh64-reg-neg.data"
              "conformance_tests/arsh64-reg.data"

              ;"conformance_tests/be16-high.data" 
              ;"conformance_tests/be16.data" 
              ;"conformance_tests/be32-high.data" 
              ;"conformance_tests/be32.data" 
              ;"conformance_tests/be64.data" 
              ;"conformance_tests/call_local.data" 
              ;"conformance_tests/call_unwind_fail.data" 
              ;"conformance_tests/callx.data" 
              "conformance_tests/div32-by-zero-reg-2.data"
              "conformance_tests/div32-by-zero-reg.data"
              "conformance_tests/div32-high-divisor.data"
              "conformance_tests/div32-imm.data"
              "conformance_tests/div32-by-zero-reg-2.data"
              "conformance_tests/div32-reg.data"
              "conformance_tests/div64-by-zero-reg.data"

              "conformance_tests/div64-imm.data"
              ;"conformance_tests/div64-negative-imm.data"  
              ;"conformance_tests/div64-negative-reg.data"  
              "conformance_tests/div64-reg.data"
              ;"conformance_tests/exit-not-last.data" 
              "conformance_tests/exit.data"
              ;"conformance_tests/ja32.data" 
              "conformance_tests/jeq-imm.data"
              "conformance_tests/jeq-reg.data"
              "conformance_tests/jeq32-imm.data"
              "conformance_tests/jeq32-reg.data"
              "conformance_tests/jge-imm.data"
              "conformance_tests/jge-reg.data"
              "conformance_tests/jge32-imm.data"
              "conformance_tests/jge32-reg.data"

              ;"conformance_tests/jgt-imm.data" 
              ;"conformance_tests/jgt-reg.data" 
              ;"conformance_tests/jgt32-imm.data" 
              ;"conformance_tests/jgt32-reg.data" 
              "conformance_tests/jit-bounce.data"
              ;;"conformance_tests/jle-imm.data" 
              "conformance_tests/jle-reg.data"
              "conformance_tests/jle32-imm.data"
              "conformance_tests/jle32-reg.data"
              "conformance_tests/jlt-imm.data"
              "conformance_tests/jlt-reg.data"
              "conformance_tests/jlt32-imm.data"
              "conformance_tests/jlt32-reg.data"
              "conformance_tests/jne-reg.data"
              "conformance_tests/jne32-imm.data"
              "conformance_tests/jne32-reg.data"

              "conformance_tests/jset-imm.data"
              "conformance_tests/jset-reg.data"
              "conformance_tests/jset32-imm.data"
              "conformance_tests/jset32-reg.data"
              "conformance_tests/jsge-imm.data" 
              "conformance_tests/jsge-reg.data" 
              "conformance_tests/jsge32-imm.data" 
              "conformance_tests/jsge32-reg.data" 
              "conformance_tests/jsgt-imm.data" 
              "conformance_tests/jsgt-reg.data"
              "conformance_tests/jsgt32-imm.data" 
              "conformance_tests/jsgt32-reg.data" 
              "conformance_tests/jsle-imm.data" 
              "conformance_tests/jsle-reg.data" 
              "conformance_tests/jsle32-imm.data" 
              "conformance_tests/jsle32-reg.data" 
              "conformance_tests/jslt-imm.data" 
              "conformance_tests/jslt-reg.data" 
              "conformance_tests/jslt32-imm.data" 
              "conformance_tests/jslt32-reg.data" 

              ;;"conformance_tests/lddw.data" 
              ;;"conformance_tests/lddw2.data" 
              ;;"conformance_tests/ldxb-all.data" 
              ;;"conformance_tests/ldxb.data" 
              ;;"conformance_tests/ldxdw.data" 
              ;;"conformance_tests/ldxh-all.data" 
              ;;"conformance_tests/ldxh-all2.data" 
              ;;"conformance_tests/ldxh-same-reg.data" 
              ;;"conformance_tests/ldxh.data" 
              ;;"conformance_tests/ldxw-all.data" 
              ;;"conformance_tests/ldxw.data" 
              ;;"conformance_tests/le16.data" 
              ;;"conformance_tests/le32.data" 
              ;;"conformance_tests/le64.data" 

              ;;"conformance_tests/lock_add.data" 
              ;;"conformance_tests/lock_add32.data" 
              ;;"conformance_tests/lock_and.data" 
              ;;"conformance_tests/lock_and32.data" 
              ;;"conformance_tests/lock_cmpxch.data" 
              ;;"conformance_tests/lock_cmpxch32.data" 
              ;;"conformance_tests/lock_fetch_add.data" 
              ;;"conformance_tests/lock_fetch_add32.data" 
              ;;"conformance_tests/lock_fetch_and.data" 
              ;;"conformance_tests/lock_fetch_and32.data" 
              ;;"conformance_tests/lock_fetch_or.data" 
              ;;"conformance_tests/lock_fetch_or32.data" 
              ;;"conformance_tests/lock_fetch_xor.data" 
              ;;"conformance_tests/lock_fetch_xor32.data" 
              ;;"conformance_tests/lock_or.data" 
              ;;"conformance_tests/lock_or32.data" 
              ;;"conformance_tests/lock_xchg.data" 
              ;;"conformance_tests/lock_xchg32.data" 
              ;;"conformance_tests/lock_xor.data" 
              ;;"conformance_tests/lock_xor32.data" 

              "conformance_tests/lsh32-imm-high.data"
              "conformance_tests/lsh32-imm-neg.data"
              "conformance_tests/lsh32-imm.data"
              "conformance_tests/lsh32-reg-high.data"
              "conformance_tests/lsh32-reg-neg.data"
              "conformance_tests/lsh32-reg.data"
              "conformance_tests/lsh64-imm-high.data"
              "conformance_tests/lsh64-imm-neg.data"
              "conformance_tests/lsh64-imm.data"
              "conformance_tests/lsh64-reg-high.data"
              "conformance_tests/lsh64-reg-neg.data"
              "conformance_tests/lsh64-reg.data"

              ;;"conformance_tests/mem-len.data" 
              "conformance_tests/mod-by-zero-reg.data"
              "conformance_tests/mod.data"
              "conformance_tests/mod32.data"
              "conformance_tests/mod64-by-zero-reg.data"
              "conformance_tests/mod64.data"
              "conformance_tests/mov.data"
              "conformance_tests/mov64.data"
              ;;"conformance_tests/movsx1632-reg.data" 
              ;;"conformance_tests/movsx1664-reg.data" 
              ;;"conformance_tests/movsx3264-reg.data" 
              ;;"conformance_tests/movsx832-reg.data" 
              ;;"conformance_tests/movsx864-reg.data" 
              "conformance_tests/mul32-imm.data"
              "conformance_tests/mul32-reg-overflow.data"
              "conformance_tests/mul32-reg.data"
              "conformance_tests/mul64-imm.data"
              "conformance_tests/mul64-reg.data"
              "conformance_tests/neg.data"
              "conformance_tests/neg64.data"
              ;;"conformance_tests/prime.data"

              "conformance_tests/rsh32-imm-high.data" 
              "conformance_tests/rsh32-imm-neg.data" 
              "conformance_tests/rsh32-imm.data" 
              "conformance_tests/rsh32-reg-high.data" 
              "conformance_tests/rsh32-reg-neg.data" 
              "conformance_tests/rsh32-reg.data" 
              "conformance_tests/rsh64-imm-high.data"
              "conformance_tests/rsh64-imm-neg.data"
              "conformance_tests/rsh64-imm.data"
              "conformance_tests/rsh64-reg-high.data"
              "conformance_tests/rsh64-reg-neg.data"
              "conformance_tests/rsh64-reg.data"

              "conformance_tests/sdiv32-by-zero-imm.data"
              "conformance_tests/sdiv32-by-zero-reg.data"
              "conformance_tests/sdiv32-imm.data"
              "conformance_tests/sdiv32-reg.data"
              "conformance_tests/sdiv64-by-zero-imm.data"
              "conformance_tests/sdiv64-by-zero-reg.data"
              "conformance_tests/sdiv64-imm.data"
              "conformance_tests/sdiv64-reg.data"
              "conformance_tests/smod32-neg-by-neg-imm.data"
              "conformance_tests/smod32-neg-by-neg-reg.data"
              "conformance_tests/smod32-neg-by-pos-imm.data"
              "conformance_tests/smod32-neg-by-pos-reg.data"
              "conformance_tests/smod32-neg-by-zero-imm.data"
              "conformance_tests/smod32-neg-by-zero-reg.data"
              "conformance_tests/smod32-pos-by-neg-imm.data"
              "conformance_tests/smod32-pos-by-neg-reg.data"
              "conformance_tests/smod64-neg-by-neg-imm.data"
              "conformance_tests/smod64-neg-by-neg-reg.data"
              "conformance_tests/smod64-neg-by-pos-imm.data"
              "conformance_tests/smod64-neg-by-pos-reg.data"
              "conformance_tests/smod64-neg-by-zero-imm.data"
              "conformance_tests/smod64-neg-by-zero-reg.data"
              "conformance_tests/smod64-pos-by-neg-imm.data"
              "conformance_tests/smod64-pos-by-neg-reg.data"

              ;;"conformance_tests/stack.data" 
              ;;"conformance_tests/stb.data" 
              ;;"conformance_tests/stdw.data" 
              ;;"conformance_tests/sth.data" 
              ;;"conformance_tests/stw.data" 
              ;;"conformance_tests/stxb-all.data" 
              ;;"conformance_tests/stxb-all2.data" 
              ;;"conformance_tests/stxb-chain.data" 
              ;;"conformance_tests/stxb.data" 
              ;;"conformance_tests/.data" 
              ;;"conformance_tests/stxdw.data" 
              ;;"conformance_tests/stxh.data" 
              ;;"conformance_tests/stxw.data" 
              ;;"conformance_tests/subnet.data" 
              ;;"conformance_tests/swap16.data" 
              ;;"conformance_tests/swap32.data" 
              ;;"conformance_tests/swap64.data"
              ))
  )
(define (execFiles input)
  (for ([i input])
  (display i)
  (display "====>>")
  (display (fileCompare i))
  (display "\n"))
)

(execFiles fileInput)
