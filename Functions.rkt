#lang racket

(require redex
         ;racket
         "EBPF.rkt"
         sketching
         )

(provide (all-defined-out))


(define-metafunction ebpf
  at : pc instr -> word
  [(at 0 () ) (0 0  rP rP eof)]
  [(at 0 (word_1 word_2 ...) ) word_1] 
  [(at number (word_1 word_2 ...)) (at ,(- (term number) 1 ) (word_2 ...))]
  [(at number () ) (0 0  rP rP eof)]
)

(define-metafunction ebpf
  instrSize : instr -> number
  [(instrSize ()) 0]
  [(instrSize (word_1 word_2 ...) ) (+ (term 1) (instrSize (word_2 ...)))]
)

(define-metafunction ebpf
  regread : registers destinationReg -> number
  [(regread () registerCode_1) -1]
  [(regread ((registerCode_1 content_1) (registerCode_2 content_2) ...) registerCode_1) content_1] 
  [(regread ((registerCode_10 content_1) (registerCode_2 content_2) ...) registerCode_1) (regread ((registerCode_2 content_2) ...) registerCode_1)]
)

(define-metafunction ebpf
  regwrite : registers destinationReg number -> registers
  [(regwrite () registerCode_1 content_1) ()]
  [(regwrite ((registerCode_1 content_10) (registerCode_2 content_2) ...) registerCode_1 content_1) ((registerCode_1 content_1) (registerCode_2 content_2) ...)] ;; Caso base pc 0 lista de palavras retornando word_1
  [(regwrite ((registerCode_10 content_10) (registerCode_2 content_2) ...) registerCode_1 content_1) (insert (regwrite ((registerCode_2 content_2) ...) registerCode_1 content_1) (registerCode_10 content_10) )]
  )
(define-metafunction ebpf
  regwriteaux : registers destinationReg number registers -> registers
  [(regwriteaux () registerCode_1 content_1 registers_1) registers_1]
  [(regwriteaux ((registerCode_1 content_10) (registerCode_2 content_2) ...) registerCode_1 content_1 (register_10 ...)) (register_10 ... (registerCode_1 content_1) (registerCode_2 content_2) ...)] ;; Caso base pc 0 lista de palavras retornando word_1
  [(regwriteaux ((registerCode_10 content_10) (registerCode_2 content_2) ...) registerCode_1 content_1 (register_10 ...)) (regwriteaux ((registerCode_2 content_2) ...) registerCode_1 content_1(register_10 ...(registerCode_10 content_10) ))]
)
(define-metafunction ebpf
  insert : registers register -> registers
  [(insert () register_1) (register_1)]
  [(insert ( register_2 register_3 ...) register_1) (register_1 register_2 register_3 ...)] 
)
(define-metafunction ebpf
  and : number number -> number
  [(and 0 number_11 ) 0 ]
  [(and number_10 0 ) 0 ]
  [(and number_1 number_2 ) number_1 ]
)
(define-metafunction ebpf
  or : number number -> number
  [(or 0 0 ) 0 ]
  [(or 0 number_2 ) number_2 ]
  [(or number_1 0 ) number_1 ]
  [(or number_1 number_2 ) number_1 ]
)
(define-metafunction ebpf
  xor : number number -> number
  [(xor 0 0 ) 0 ]
  [(xor 0 number_2 ) number_2 ]
  [(xor number_1 0 ) number_1 ]
  [(xor number_1 number_2 ) 0 ]
)
(define-metafunction ebpf
  lsh2 : number number -> number
  [(lsh2 number_1 number_2 ) ,(term(arithmetic-shift number_1 number_2)) ]
)
(define-metafunction ebpf
  lsh : number number number -> number
  [(lsh number_1 number_2 number_3) number_13
  (where boolean_21 ,(< 0 (term number_2)))                                
  (where number_21 ,(if (term boolean_21) (term number_2) (+ (term number_2) (term number_3) )))
  (where number_22 ,(modulo (term number_21) (term number_3)))
  (where number_11 ,(arithmetic-shift (term number_1) (term number_22)))
  (where string_1 ,(binary (term number_11)))
  (where number_23 ,(unbinary (term string_1)))
  (where number_12 ,(string-length (term string_1)))
  (where boolean_1 ,(< (term number_12) (term number_3)))
  (where number_13 ,(if (term boolean_1) (term number_23) (unbinary(substring (term string_1) (- (term number_12) (term number_3))))))
  ]
)
(define-metafunction ebpf
  rsh : number number number -> number
  [(rsh number_1 number_2 number_3) number_13
  (where boolean_21 ,(< 0 (term number_2)))                            
  (where number_21 ,(if (term boolean_21) (term number_2) (+ (term number_2) (term number_3) )))
  (where number_22 ,(modulo (term number_21) (term number_3)))
  (where number_11 ,(arithmetic-shift (term number_1) (*(term number_22) -1)))
  (where string_1 ,(binary (term number_11)))
  (where number_23 ,(unbinary (term string_1)))
  (where number_12 ,(string-length (term string_1)))
  (where boolean_1 ,(< (term number_12) (term number_3)))
  (where number_13 ,(if (term boolean_1) (term number_23) (unbinary(substring (term string_1) 0 (term number_3)))))
  ]
)
(define-metafunction ebpf
  arsh : number number number -> number
  [(arsh number_1 number_2 number_3) number_13
  (where boolean_21 ,(< 0 (term number_2)))                              
  (where number_21 ,(if (term boolean_21) (term number_2) (+ (term number_2) (term number_3) )))
  (where number_22 ,(modulo (term number_21) (term number_3)))
  (where number_11 ,(arithmetic-shift (term number_1) (*(term number_22) -1)))
  (where string_1 ,(binary (term number_11)))
  (where string_2 ,(~a (make-string (term number_22) #\1 ) (term string_1)))
  (where number_23 ,(unbinary (term string_2)))
  (where number_12 ,(string-length (term string_1)))
  (where boolean_1 ,(< (term number_12) (term number_3)))
  (where number_13 ,(if (term boolean_1) (term number_23) (unbinary(substring (term string_2) 0 (term number_3)))))
  ]
)
(define-metafunction ebpf
  bitTrim : number number -> number
  [(bitTrim number_1 number_2 ) number_13
  (where string_1 ,(binary (term number_1)))
  (where number_11 ,(string-length (term string_1)))
  (where boolean_1 ,(<= (term number_11) (term number_2)))
  (where number_13 ,(if (term boolean_1) (term number_1) (unbinary(substring (term string_1) (- (term number_11) (term number_2))))))
  ]
)
(define-metafunction ebpf
  returnSigned : number -> number
  [(returnSigned number_1 ) number_10
   (where number_2 ,(- (term number_1) 1 ))
   (where string_1 ,(binary (term number_2)))
   (where string_2 ,(string-replace (term string_1) "1" "a"))
   (where string_3 ,(string-replace (term string_2) "0" "1"))
   (where string_4 ,(string-replace (term string_3) "a" "0"))
   (where number_10 ,(* (unbinary (term string_4)) -1) ) 
   ]
 )

(define-metafunction ebpf
  negCast : number number -> number
  [(negCast number_1 number_2 ) number_10
   (where number_3 ,(if (< (term number_1) 0) (* (term number_1) -1 ) (term number_1) ))
   (where string_1 ,(binary (term number_3)))
   (where string_2 ,(~a (make-string (- (term number_2) (string-length (term string_1)) ) #\0 ) (term string_1) ))
   (where string_3 ,(string-replace (term string_2) "1" "a"))
   (where string_4 ,(string-replace (term string_3) "0" "1"))
   (where string_5 ,(string-replace (term string_4) "a" "0"))
   (where number_6 ,(unbinary (term string_5)))
   (where number_10 ,(+ (term number_6) 1 ))
   ]
 )

(define-metafunction ebpf
  rsh2 : number number -> number
  [(rsh2 number_1 number_2 ) (arithmetic-shift number_1 ,(-(term number_2)(term -1))) ]
)
(define-metafunction ebpf
  neg : number number -> number
  [(neg number_1 number_2) number_10
   (where string_1 ,(binary (term number_1)))
   (where string_2 ,(~a (make-string (- (term number_2) (string-length (term string_1)) ) #\0 ) (term string_1) ))
   (where string_3 ,(string-replace (term string_2) "1" "a"))
   (where string_4 ,(string-replace (term string_3) "0" "1"))
   (where string_5 ,(string-replace (term string_4) "a" "0"))
   (where number_10 ,(unbinary (term string_5)))
   ]
)

(define-metafunction ebpf
  compare : number number offset symbol number -> offset
  [(compare number_1 number_2 offset_1 equal number_5      ) number_10
   (where boolean_1 ,(= (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]
  
  [(compare number_1 number_2 offset_1 diff number_5      ) number_10
   (where boolean_1 ,(not(= (term number_1) (term number_2))))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]
  
  [(compare number_1 number_2 offset_1 less-eq number_5      ) number_10
   (where boolean_1 ,(<= (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare number_1 number_2 offset_1 less number_5      ) number_10
   (where boolean_1 ,(< (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare number_1 number_2 offset_1 greater-eq number_5      ) number_10
   (where boolean_1 ,(>= (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare number_1 number_2 offset_1 greater number_5      ) number_10
   (where boolean_1 ,(> (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare number_1 number_2 offset_1 bool-and number_5      ) number_10
   (where boolean_1 ,(not(= (bitwise-and (term number_1) (term number_2)) 0)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]
  
)

(define-metafunction ebpf
  compare-sig : number number offset symbol number number -> offset
  [(compare-sig number_1 number_2 offset_1 less-eq-sig number_5 number_6) number_10
   (where boolean_10 ,(= (string-length(binary (term number_1))) (term number_6) ))
   (where boolean_11 ,(= (string-length(binary (term number_2))) (term number_6) ))
   (where number_20 ,(if (term boolean_10) (* (unbinary(substring(binary(term number_1)) 1 )) -1) (term number_1)))
   (where number_21 ,(if (term boolean_11) (* (unbinary(substring(binary(term number_2)) 1 )) -1) (term number_2)))
   (where boolean_1 ,(<= (term number_20) (term number_21)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare-sig number_1 number_2 offset_1 less-sig number_5  number_6 ) number_10
   (where boolean_10 ,(= (string-length(binary (term number_1))) (term number_6) ))
   (where boolean_11 ,(= (string-length(binary (term number_2))) (term number_6) ))
   (where number_20 ,(if (term boolean_10) (* (unbinary(substring(binary(term number_1)) 1 )) -1) (term number_1)))
   (where number_21 ,(if (term boolean_11) (* (unbinary(substring(binary(term number_2)) 1 )) -1) (term number_2)))
   (where boolean_1 ,(< (term number_20) (term number_21)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare-sig number_1 number_2 offset_1 greater-eq-sig number_5 number_6) number_10
   (where boolean_10 ,(= (string-length(binary (term number_1))) (term number_6) ))
   (where boolean_11 ,(= (string-length(binary (term number_2))) (term number_6) ))
   (where number_20 ,(if (term boolean_10) (* (unbinary(substring(binary(term number_1)) 1 )) -1) (term number_1)))
   (where number_21 ,(if (term boolean_11) (* (unbinary(substring(binary(term number_2)) 1 )) -1) (term number_2)))
   (where boolean_1 ,(>= (term number_20) (term number_21)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]

  [(compare-sig number_1 number_2 offset_1 greater-sig number_5 number_6 ) number_10
   (where boolean_10 ,(= (string-length(binary (term number_1))) (term number_6) ))
   (where boolean_11 ,(= (string-length(binary (term number_2))) (term number_6) ))
   (where number_20 ,(if (term boolean_10) (* (unbinary(substring(binary(term number_1)) 1 )) -1) (term number_1)))
   (where number_21 ,(if (term boolean_11) (* (unbinary(substring(binary(term number_2)) 1 )) -1) (term number_2)))
   (where boolean_1 ,(> (term number_20) (term number_21)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (+ (term offset_1) 1)) 1))]
)

(define-metafunction ebpf
  compareEQ : number number offset symbol number -> offset
  [(compareEQ number_1 number_2 offset_1 equal number_5      ) number_10
   (where boolean_1 ,(= (term number_1) (term number_2)))
   (where boolean_2 ,(equal? (term offset_1) (term ext)))
   (where number_10 ,(if (term boolean_1) (if (term boolean_2) (term number_5) (term offset_1)) 1))
   ]
)
(define-metafunction ebpf
  compareBool : number number offset boolean number -> offset
  [(compareBool number_1 number_2 offset_1 #f number_3 ) 1]
  [(compareBool number_1 number_2 ext #f number_5     ) 1]
  [(compareBool number_1 number_2 ext #t number_5      ) number_5]
  [(compareBool number_1 number_2 offset_1 #t number   ) offset_1]
)

(define-metafunction ebpf
  compare-less : number number number -> number
  [(compare-less number_1     0     number_3 ) 1]
  [(compare-less    0      number_1 number_3 ) number_3]
  [(compare-less number_1  number_2 number_3 ) (compare-less ,(-(term number_1)(term 1)) ,(-(term number_2)(term 1)) number_3)]
)
(define-metafunction ebpf
  compare-greater : number number number -> number
  [(compare-greater number_1     0     number_3 ) number_3]
  [(compare-greater    0      number_1 number_3 ) 1]
  [(compare-greater number_1  number_2 number_3 ) (compare-greater ,(-(term number_1)(term 1)) ,(-(term number_2)(term 1)) number_3)]
)