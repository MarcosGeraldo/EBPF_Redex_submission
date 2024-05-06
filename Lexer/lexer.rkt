
#lang racket
 
(require parser-tools/lex
         (prefix-in : parser-tools/lex-sre))
 
 
(define-tokens value-tokens (NUMBER HEX) )
(define-empty-tokens op-tokens (ASM RESULT EXIT EOF MOV MOV32 SEP
                                REG ADD ADD32 SUB SUB32 MUL MUL32 DIV DIV32 SDIV SDIV32 MOD MOD32 SMOD SMOD32 NEG NEG32 NEWLINE
                                OR OR32 XOR XOR32 AND AND32
                                TRASH JNE JGE JGE32 JNE32 JEQ JEQ32 JGT JGT32 JLE JLE32 JLT JLT32
                                JSET JSGE JSGT JSLE JSET32 JSLT JSLT32 JSGE32 JSGT32 JSLE32
                                LSH LSH32 RSH RSH32 ARSH ARSH32))
(define-lex-abbrev hex-number (:: "0x" (:+ (:or numeric (char-range #\a #\f)(char-range #\A #\F)))))
(define-lex-abbrev comment (:: "#" (complement (:: any-string #\newline any-string)) #\newline))
(define next-token
  (lexer-src-pos
   [(eof) (token-EOF)]
   [(:+ (:& (:~ #\newline) whitespace)) (return-without-pos (next-token input-port))]
   ["," (token-SEP)]
   ["%r" (token-REG)]
   ["exit" (token-EXIT)]
   ["-- result\n" (token-RESULT)]
   ["-- asm" (token-ASM)]
   ["mov" (token-MOV)]
   ["mov32" (token-MOV32)]
   ["neg" (token-NEG)]
   ["neg32" (token-NEG32)]
   ["mod" (token-MOD)]
   ["mod32" (token-MOD32)]
   ["smod" (token-SMOD)]
   ["smod32" (token-SMOD32)]
   ["lddw" (token-MOV)]
   ["lddw32" (token-MOV32)]
   ["add" (token-ADD)]
   ["add32" (token-ADD32)]
   ["sub" (token-SUB)]
   ["sub32" (token-SUB32)]
   ["mul" (token-MUL)]
   ["mul32" (token-MUL32)]
   ["div" (token-DIV)]
   ["div32" (token-DIV32)]
   ["sdiv" (token-SDIV)]
   ["sdiv32" (token-SDIV32)]
   ["or" (token-OR)]
   ["or32" (token-OR32)]
   ["and" (token-AND)]
   ["and32" (token-AND32)]
   ["xor" (token-XOR)]
   ["xor32" (token-XOR32)]

   ["jset" (token-JSET)]
   ["jset32" (token-JSET32)]
   ["jsge" (token-JSGE)]
   ["jsge32" (token-JSGE32)]
   ["jsgt" (token-JSGT)]
   ["jsgt32" (token-JSGT32)]
   ["jsle" (token-JSLE)]
   ["jsle32" (token-JSLE32)]
   ["jslt" (token-JSLT)]
   ["jslt32" (token-JSLT32)]
   
   ["jle" (token-JLE)]
   ["jle32" (token-JLE32)]
   ["jne" (token-JNE)]
   ["jne32" (token-JNE32)]
   ["jlt" (token-JLT)]
   ["jlt32" (token-JLT32)]
   ["jge" (token-JGE)]
   ["jge32" (token-JGE32)]
   ["jgt" (token-JGT)]
   ["jgt32" (token-JGT32)]
   ["jeq" (token-JEQ)]
   ["jeq32" (token-JEQ32)]
   ["lsh" (token-LSH)]
   ["lsh32" (token-LSH32)]
   ["arsh" (token-ARSH)]
   ["arsh32" (token-ARSH32)]
   ["rsh" (token-RSH)]
   ["rsh32" (token-RSH32)]
   [hex-number (token-HEX (string->number (string-append "#x" (substring lexeme 2))))]
   [comment (token-TRASH)]
   [#\newline (token-NEWLINE)]
   [(:: (:* #\-) (:* #\+) (:+ numeric) (:* (:: #\. (:+ numeric) ))) (token-NUMBER (string->number lexeme))]))
 
 
(provide value-tokens op-tokens next-token)