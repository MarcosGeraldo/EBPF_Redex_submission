#lang racket

(require redex
         "EBPF.rkt"
         "Functions.rkt")

(provide (all-defined-out))


(define ->exe
  (reduction-relation
   ebpf
   #:domain program
   #:codomain program
   
   ;;Regra BPF_add com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-add bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(+ (term immediate_1) (term number_1) )))
        )
   ;;Fechamento da regra BPF_add com bpf-k
   
   ;;Regra BPF_sub com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sub bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 ,(- (term number_1) (term immediate_1)))
         (where number_3 ,(if (>= (term number_2) 0) (term number_2) (term(negCast number_2 64))) )
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_sub com bpf-k

      ;;Regra BPF_sub com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sub bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where number_3 ,(- (term number_1) (term number_2)))
         (where number_4 ,(if (>= (term number_3) 0) (term number_3) (term(negCast number_3 64))) )
         (where registers_1 (regwrite registers_0 destinationReg number_4))
        )
   ;;Fechamento da regra BPF_sub com bpf-x

      ;;Regra BPF_sub32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sub32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 ,(- (term number_1) (term immediate_1)))
         (where number_3 ,(if (>= (term number_2) 0) (term number_2) (term(negCast number_2 32))) )
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_sub32 com bpf-k

      ;;Regra BPF_sub32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sub32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where number_3 ,(- (term number_1) (term number_2)))
         (where number_4 ,(if (>= (term number_3) 0) (term number_3) (term(negCast number_3 32))) )
         (where registers_1 (regwrite registers_0 destinationReg number_4))
        )
   ;;Fechamento da regra BPF_sub32 com bpf-x
   
   ;;Regra BPF_mul com bpf-k
  (--> ( registers_0 instr_1 pc_1 )
       (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mul bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64))
         (where number_3 (bitTrim ,(* (term number_1) (term number_2) ) 64))
         (where registers_1 (regwrite registers_0 destinationReg number_3)))
   ;;Fechamento da regra BPF_mul com bpf-k

  ;;Regra BPF_mul com bpf-x
  (--> ( registers_0 instr_1 pc_1 )
       (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mul bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64))
         (where number_3 (bitTrim ,(* (term number_1) (term number_2) ) 64))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mul com bpf-x

     ;;Regra BPF_mul32 com bpf-k
  (--> ( registers_0 instr_1 pc_1 )
       (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mul32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32))
         (where number_3 (bitTrim ,(* (term number_1) (term number_2) ) 32))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mul32 com bpf-k

  ;;Regra BPF_mul32 com bpf-x
  (--> ( registers_0 instr_1 pc_1 )
       (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mul32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32))
         (where number_3 (bitTrim ,(* (term number_1) (term number_2) ) 32))
         (where registers_1 (regwrite registers_0 destinationReg number_3)))
   ;;Fechamento da regra BPF_mul32 com bpf-x
  
   ;;Regra BPF_div com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-div bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64))
         (where number_3 ,(if (= 0 (term immediate_1)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_4 (bitTrim number_3 64))
         (where registers_1 (regwrite registers_0 destinationReg number_4))
        )
   ;;Fechamento da regra BPF_div com bpf-k

   ;;Regra BPF_div32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-div32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32))
         (where number_3 ,(if (= 0 (term immediate_1)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_4 (bitTrim number_3 32))
         (where registers_1 (regwrite registers_0 destinationReg number_4))(where registers_1 (regwrite registers_0 destinationReg number_4))
        )
   ;;Fechamento da regra BPF_div32 com bpf-k

   ;;Regra BPF_div com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-div bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2))) ))
         (where number_4 (bitTrim number_3 64))
         (where registers_1 (regwrite registers_0 destinationReg number_4))
         )
   ;;Fechamento da regra BPF_div com bpf-x

   ;;Regra BPF_div32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-div32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2))) ))
         (where number_4 (bitTrim number_3 32))
         (where registers_1 (regwrite registers_0 destinationReg number_4))
         )
   ;;Fechamento da regra BPF_div32 com bpf-x

   ;;Regra BPF_sdiv com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sdiv bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64))
         (where number_3 (returnSigned number_1))
         (where number_4 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_5 ,(if (< (term number_4) 0) (term (negCast number_4 64)) (term number_4)))
         (where registers_1 (regwrite registers_0 destinationReg number_5))
        )
   ;;Fechamento da regra BPF_sdiv com bpf-k

   ;;Regra BPF_sdiv32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sdiv32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32))
         (where number_3 (returnSigned number_1))
         (where number_4 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_5 ,(if (< (term number_4) 0) (term (negCast number_4 32)) (term number_4)))
         (where registers_1 (regwrite registers_0 destinationReg number_5))
         )
   ;;Fechamento da regra BPF_sdiv32 com bpf-k

   ;;Regra BPF_sdiv com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sdiv bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64))
         (where number_3 (returnSigned number_1))
         (where number_4 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_5 ,(if (< (term number_4) 0) (term (negCast number_4 64)) (term number_4)))
         (where registers_1 (regwrite registers_0 destinationReg number_5))
         )
   ;;Fechamento da regra BPF_sdiv com bpf-x

   ;;Regra BPF_sdiv32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-sdiv32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32))
         (where number_3 (returnSigned number_1))
         (where number_4 ,(if (= 0 (term number_2)) 0 (numerator(/ (term number_1) (term number_2)))))
         (where number_5 ,(if (< (term number_4) 0) (term (negCast number_4 32)) (term number_4)))
         (where registers_1 (regwrite registers_0 destinationReg number_5))
         )
   ;;Fechamento da regra BPF_sdiv32 com bpf-x
   
   ;;Regra BPF_add com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-add bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(+ (term number_1) (term number_2) )))
        )
   ;;Fechamento da regra BPF_add com bpf-x

   ;;Regra BPF_or com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-and bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-and (term number_1) (term immediate_1))))
        )
   ;;Fechamento da regra BPF_or com bpf-k
   
   ;;Regra BPF_and com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-or bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-ior(term number_1) (term immediate_1))))
        )
   ;;Fechamento da regra BPF_and com bpf-k
   
   ;;Regra BPF_lsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-lsh bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg (lsh number_1 immediate_1 64)))
        )
   ;;Fechamento da regra BPF_lsh com bpf-k

      ;;Regra BPF_lsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-lsh32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg (lsh number_1 immediate_1 32)))
        )
   ;;Fechamento da regra BPF_lsh com bpf-k
   
   ;;Regra BPF_rsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-rsh32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg)32))
         (where number_2 ,(* (term (bitTrim immediate_1 32)) (term -1)))
         (where registers_1 (regwrite registers_0 destinationReg (rsh number_1 immediate_1 32)))
        )
   ;;Fechamento da regra BPF_rsh com bpf-k

      ;;Regra BPF_rsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-rsh bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg)64))
         (where number_2 ,(* (term (bitTrim immediate_1 64)) (term -1)))
         (where registers_1 (regwrite registers_0 destinationReg (rsh number_1 immediate_1 64)))
        )
   ;;Fechamento da regra BPF_rsh com bpf-k

   ;;Regra BPF_rsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-rsh32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg) 32))
         (where number_2 (bitTrim(regread registers_0 sourceReg) 32))
         (where number_3 ,(* (term number_2)(term -1)))
         (where registers_1 (regwrite registers_0 destinationReg (rsh number_1 number_2 32)))
        )
   ;;Fechamento da regra BPF_rsh com bpf-x
   
   ;;Regra BPF_rsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-rsh bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg) 64))
         (where number_2 (bitTrim(regread registers_0 sourceReg) 64))
         (where number_3 ,(* (term number_2)(term -1)))
         (where registers_1 (regwrite registers_0 destinationReg (rsh number_1 number_2 64)))
        )
   ;;Fechamento da regra BPF_rsh com bpf-x
   
   ;;Regra BPF_neg 
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate offset sourceReg destinationReg_1 (bpf-neg bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg_1) 64 ))
         (where registers_1 (regwrite registers_0 destinationReg_1 (negCast number_1 64)))
        )
   ;;Fechamento da regra BPF_neg

      ;;Regra BPF_neg32
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate offset sourceReg destinationReg_1 (bpf-neg32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim(regread registers_0 destinationReg_1)32 ))
         (where registers_1 (regwrite registers_0 destinationReg_1 (negCast number_1 32)))
        )
   ;;Fechamento da regra BPF_neg32
   
   ;;Regra BPF_mod com bpf-k
   
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mod bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64))
         (where number_3 ,(if (= (term number_2) 0) (term number_1) (modulo (term number_1)(term number_2)) ))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mod com bpf-k

      ;;Regra BPF_mod com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mod bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64))
         (where number_3 ,(if (= (term number_2) 0) (term number_1) (modulo (term number_1)(term number_2)) ))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mod com bpf-x

      ;;Regra BPF_mod32 com bpf-k
   
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mod32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32))
         (where number_3 ,(if (= (term number_2) 0) (term number_1) (modulo (term number_1)(term number_2)) ))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mod32 com bpf-k

      ;;Regra BPF_mod32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mod32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32))
         (where number_3 ,(if (= (term number_2) 0) (term number_1) (modulo (term number_1)(term number_2)) ))
         (where registers_1 (regwrite registers_0 destinationReg number_3))
        )
   ;;Fechamento da regra BPF_mod32 com bpf-x

   ;;Regra BPF_smod com bpf-k
   
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-smod bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64))
         (where number_3 ,(if (>= (term number_1) 0) (term number_1) (* (term number_1) -1) ))
         (where number_4 ,(if (>= (term number_2) 0) (term number_2) (* (term number_2) -1) ))
         (where number_5 ,(if (= 0 (term number_4)) (term number_3) (modulo (term number_3) (term number_4))))
         (where number_6 ,(if (>= (term number_1) 0) (term number_5) (* (term number_5) -1) ))
         (where number_7 ,(if (< (term number_6) 0) (term (negCast number_6 64)) (term number_6)))
         (where registers_1 (regwrite registers_0 destinationReg number_7))
        )
   ;;Fechamento da regra BPF_smod com bpf-k

      ;;Regra BPF_smod com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-smod bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64))
         (where number_3 ,(if (>= (term number_1) 0) (term number_1) (* (term number_1) -1) ))
         (where number_4 ,(if (>= (term number_2) 0) (term number_2) (* (term number_2) -1) ))
         (where number_5 ,(if (= 0 (term number_4)) (term number_3) (modulo (term number_3) (term number_4))))
         (where number_6 ,(if (>= (term number_1) 0) (term number_5) (* (term number_5) -1) ))
         (where number_7 ,(if (< (term number_6) 0) (term (negCast number_6 64)) (term number_6)))
         (where registers_1 (regwrite registers_0 destinationReg number_7))
        )
   ;;Fechamento da regra BPF_smod com bpf-x

      ;;Regra BPF_smod32 com bpf-k
   
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-smod32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32))
         (where number_3 ,(if (>= (term number_1) 0) (term number_1) (* (term number_1) -1) ))
         (where number_4 ,(if (>= (term number_2) 0) (term number_2) (* (term number_2) -1) ))
         (where number_5 ,(if (= 0 (term number_4)) (term number_3) (modulo (term number_3) (term number_4))))
         (where number_6 ,(if (>= (term number_1) 0) (term number_5) (* (term number_5) -1) ))
         (where number_7 ,(if (< (term number_6) 0) (term (negCast number_6 32)) (term number_6)))
         (where registers_1 (regwrite registers_0 destinationReg number_7))
        )
   ;;Fechamento da regra BPF_smod32 com bpf-k

      ;;Regra BPF_smod32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-smod32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32))
         (where number_3 ,(if (>= (term number_1) 0) (term number_1) (* (term number_1) -1) ))
         (where number_4 ,(if (>= (term number_2) 0) (term number_2) (* (term number_2) -1) ))
         (where number_5 ,(if (= 0 (term number_4)) (term number_3) (modulo (term number_3) (term number_4))))
         (where number_6 ,(if (>= (term number_1) 0) (term number_5) (* (term number_5) -1) ))
         (where number_7 ,(if (< (term number_6) 0) (term (negCast number_6 32)) (term number_6)))
         (where registers_1 (regwrite registers_0 destinationReg number_7))
        )
   ;;Fechamento da regra BPF_smod32 com bpf-x
   
   ;;Regra BPF_xor com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-xor bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-xor (term number_1) (term immediate_1))))
        )
   ;;Fechamento da regra BPF_xor com bpf-k
   
   ;;Regra BPF_mov com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mov bpf-k bpf-alu)) (at pc_1 instr_1) )
         ;(where number_1 ,(if (>= (term immediate_1) 0) (term immediate_1) (term (negCast immediate_1 64))))
         (where registers_1 (regwrite registers_0 destinationReg immediate_1))
        )
   ;;Fechamento da regra BPF_mov com bpf-k

      ;;Regra BPF_mov32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mov32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         ;(where number_1 ,(if (>= (term immediate_1) 0) (term immediate_1) (term (negCast immediate_1 64))))
         (where registers_1 (regwrite registers_0 destinationReg immediate_1))
        )
   ;;Fechamento da regra BPF_mov32 com bpf-k
   
   ;;Regra BPF_arsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-arsh bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg (arsh number_1 immediate_1 64)))
        )
   ;;Fechamento da regra BPF_arsh com bpf-k

      ;;Regra BPF_arsh com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-arsh32 bpf-k bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where registers_1 (regwrite registers_0 destinationReg (arsh number_1 immediate_1 32)))
        )
   ;;Fechamento da regra BPF_arsh com bpf-k
   
   ;;Regra BPF_end com bpf-k
   ;;Fechamento da regra BPF_end com bpf-k

   ;;Regra BPF_or com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-or bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-ior (term number_1) (term number_2))))
        )
   ;;Fechamento da regra BPF_or com bpf-x
   
   ;;Regra BPF_and com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-and bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-and (term number_1) (term number_2))))
        )
   ;;Fechamento da regra BPF_and com bpf-x
   
   ;;Regra BPF_lsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-lsh bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg (lsh number_1 number_2 64)))
        )
   ;;Fechamento da regra BPF_lsh com bpf-x

      ;;Regra BPF_lsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-lsh32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg (lsh number_1 number_2 32)))
        )
   ;;Fechamento da regra BPF_lsh com bpf-x
   
   ;;Regra BPF_xor com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-xor bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg ,(bitwise-xor (term number_1) (term number_2))))
        )
   ;;Fechamento da regra BPF_xor com bpf-x
   
   ;;Regra BPF_mov com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mov bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 sourceReg))
         ;(where number_2 ,(if (>= (term number_1) 0) (term number_1) (term (negCast number_1 64))))
         (where registers_1 (regwrite registers_0 destinationReg number_1))
        )
   ;;Fechamento da regra BPF_mov com bpf-x

      ;;Regra BPF_mov32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-mov32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 sourceReg))
         ;(where number_2 ,(if (>= (term number_1) 0) (term number_1) (term (negCast number_1 32))))
         (where registers_1 (regwrite registers_0 destinationReg number_1))
        )
   ;;Fechamento da regra BPF_mov32 com bpf-x
   
   ;;Regra BPF_arsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-arsh bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg (arsh number_1 number_2 64)))
        )
   ;;Fechamento da regra BPF_arsh com bpf-x

      ;;Regra BPF_arsh com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_1 instr_1 ,(+(term pc_1)(term 1)) )
         (where (immediate_1 offset sourceReg destinationReg (bpf-arsh32 bpf-x bpf-alu)) (at pc_1 instr_1) )
         (where number_1 (regread registers_0 destinationReg))
         (where number_2 (regread registers_0 sourceReg))
         (where registers_1 (regwrite registers_0 destinationReg (arsh number_1 number_2 32)))
        )
   ;;Fechamento da regra BPF_arsh com bpf-x
   
   ;;Regra BPF_end com bpf-x
   ;;Fechamento da regra BPF_end com bpf-x
   
   ;;Regra BPF_ja
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term offset_1)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-ja bpf-x bpf-jmp)) (at pc_1 instr_1) )
    )
   ;;Fechamento da regra BPF_ja

   ;;Regra BPF_jeq com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jeq bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 equal ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jeq com bpf-x

   ;;Regra BPF_jeq com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jeq bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 equal ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jeq com bpf-k

   ;;Regra BPF_jeq32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jeq32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 equal ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jeq32 com bpf-x

   ;;Regra BPF_jeq32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jeq32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 equal ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jeq32 com bpf-k


   ;;Regra BPF_jgt com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jgt bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 greater ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jgt com bpf_x

      ;;Regra BPF_jgt com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jgt bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 greater ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jgt com bpf_k

      ;;Regra BPF_jgt32 com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jgt32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 greater ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jgt com bpf_x32

      ;;Regra BPF_jgt32 com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jgt32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 greater ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jgt32 com bpf_k
   
   ;;Regra BPF_jge com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jge bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 greater-eq ,(* (+(term pc_1)(term 1)) -1)))
    )   
   ;;Fechamento da regra BPF_jge com bpf_x

      ;;Regra BPF_jge com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jge bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 greater-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jge com bpf_k

   ;;Regra BPF_jge32 com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jge32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 greater-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jge32 com bpf_x

      ;;Regra BPF_jge32 com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jge32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 greater-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jge32 com bpf_k
   
   ;;Regra BPF_jset com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jset bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 bool-and ,(* (+(term pc_1)(term 1)) -1)))
    )   
   ;;Fechamento da regra BPF_jset com bpf_x

      ;;Regra BPF_jset com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jset bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 bool-and ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jset com bpf_k

   ;;Regra BPF_jset32 com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jset32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 bool-and ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jset32 com bpf_x

      ;;Regra BPF_jset32 com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jset32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 bool-and ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jset32 com bpf_k
     
   ;;Regra BPF_jne com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jne bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 diff ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jne com bpf-x

   ;;Regra BPF_jne com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jne bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 diff ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jne com bpf-k

   ;;Regra BPF_jne32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jne32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 diff ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jne32 com bpf-x

   ;;Regra BPF_jne32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jne32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 diff ,(* (+(term pc_1)(term 1)) -1)))
    )
   ;;Fechamento da regra BPF_jne32 com bpf-k
   
;;Regra BPF_jsgt com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsgt bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsgt com bpf-x

   ;;Regra BPF_jsgt com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsgt bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim immediate_1 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsgt com bpf-k

   ;;Regra BPF_jsgt32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsgt32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsgt32 com bpf-x

   ;;Regra BPF_jsgt32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsgt32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim immediate_1 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsgt32 com bpf-k
   
;;Regra BPF_jsge com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsge bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-eq-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsge com bpf-x

   ;;Regra BPF_jsge com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsge bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim immediate_1 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-eq-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsge com bpf-k

   ;;Regra BPF_jsge32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsge32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-eq-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsge32 com bpf-x

   ;;Regra BPF_jsge32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsge32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim immediate_1 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 greater-eq-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsge32 com bpf-k
   
    ;;Regra BPF_jlt com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jlt bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 less ,(* (+(term pc_1)(term 1)) -1)))
    )   
   ;;Fechamento da regra BPF_jlt com bpf_x

      ;;Regra BPF_jlt com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jlt bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 less ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jlt com bpf_k

   ;;Regra BPF_jlt32 com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jlt32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 less ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jlt32 com bpf_x

      ;;Regra BPF_jlt32 com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jlt32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 less ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jlt32 com bpf_k
   
   ;;Regra BPF_jle com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jle bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 64 ))
         (where number_3 (compare number_1 number_2 offset_1 less-eq ,(* (+(term pc_1)(term 1)) -1)))
    )   
   ;;Fechamento da regra BPF_jle com bpf_x

      ;;Regra BPF_jle com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jle bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 64 ))
         (where number_2 (bitTrim immediate_1 64 ))
         (where number_3 (compare number_1 number_2 offset_1 less-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jle com bpf_k

   ;;Regra BPF_jle32 com bpf_x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jle32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim (regread registers_0 sourceReg) 32 ))
         (where number_3 (compare number_1 number_2 offset_1 less-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jle32 com bpf_x

      ;;Regra BPF_jle32 com bpf_k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jle32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (bitTrim (regread registers_0 destinationReg) 32 ))
         (where number_2 (bitTrim immediate_1 32 ))
         (where number_3 (compare number_1 number_2 offset_1 less-eq ,(* (+(term pc_1)(term 1)) -1)))
         )   
   ;;Fechamento da regra BPF_jle32 com bpf_k
   
    ;;Regra BPF_jslt com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jslt bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jslt com bpf-x

   ;;Regra BPF_jslt com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jslt bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim immediate_1 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jslt com bpf-k

   ;;Regra BPF_jslt com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jslt32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jslt32 com bpf-x

   ;;Regra BPF_jslt32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jslt32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim immediate_1 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jslt32 com bpf-k
   
   ;;Regra BPF_jsle com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsle bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-eq-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsle com bpf-x

   ;;Regra BPF_jsle com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsle bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 64 )))
         (where number_2 (returnSigned (bitTrim immediate_1 64 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-eq-sig ,(* (+(term pc_1)(term 1)) -1) 64))
    )
   ;;Fechamento da regra BPF_jsle com bpf-k

   ;;Regra BPF_jsle32 com bpf-x
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsle32 bpf-x bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim (regread registers_0 sourceReg) 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-eq-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsle32 com bpf-x

   ;;Regra BPF_jsle32 com bpf-k
   (--> ( registers_0 instr_1 pc_1 )
        (registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
         (where (immediate_1 offset_1 sourceReg destinationReg (bpf-jsle32 bpf-k bpf-jmp)) (at pc_1 instr_1) )
         (where number_1 (returnSigned (bitTrim (regread registers_0 destinationReg) 32 )))
         (where number_2 (returnSigned (bitTrim immediate_1 32 )))
         (where number_3 (compare-sig number_1 number_2 offset_1 less-eq-sig ,(* (+(term pc_1)(term 1)) -1) 32))
    )
   ;;Fechamento da regra BPF_jsle32 com bpf-k
   
   ;;Regra BPF_call
   ;;Fechamento da regra BPF_call
   
   ;;Regra BPF_exit
   (--> ( registers_0 instr_1 pc_1 )
        (number_1)
        ;(registers_0 instr_1 ,(+(term pc_1)(term number_3)) )
        (where (immediate_1 offset_1 sourceReg destinationReg (bpf-exit bpf-x bpf-alu)) (at pc_1 instr_1) )
        (where number_1 (regread registers_0 r0))
         ;(where number_2 (regread registers_0 sourceReg))
         ;(where number_3 (compare number_1 number_2 offset_1 less-eq))
    )
   ;;Fechamento da regra BPF_exit
   

   )
)
