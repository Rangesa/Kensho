use super::pcode::{OpCode, PcodeOp, Varnode};



///


/// ```c
/// int example(int a, int b) {
///     int c = a + b;
///     if (c > 10) {
///         return c * 2;
///     } else {
///         return c;
///     }
/// }
/// ```
pub fn example_translation() -> Vec<PcodeOp> {
    vec![
        // 0x1000: c = a + b
        PcodeOp::binary(
            OpCode::IntAdd,
            Varnode::register(24, 4),  // RBX (c)
            Varnode::register(0, 4),   // RAX (a)
            Varnode::register(8, 4),   // RCX (b)
            0x1000
        ),

        // 0x1004: temp1 = c > 10
        PcodeOp::binary(
            OpCode::IntSLess,
            Varnode::unique(100, 1),
            Varnode::constant(10, 4),
            Varnode::register(24, 4),
            0x1004
        ),

        // 0x1008: if (!temp1) goto 0x1014
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x1014, 8), Varnode::unique(100, 1)],
            0x1008
        ),

        // 0x100C: rax = c * 2 (then branch)
        PcodeOp::binary(
            OpCode::IntMult,
            Varnode::register(0, 4),
            Varnode::register(24, 4),
            Varnode::constant(2, 4),
            0x100C
        ),

        // 0x1010: return rax
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x1010
        ),

        // 0x1014: rax = c (else branch)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::register(24, 4),
            0x1014
        ),

        // 0x1018: return rax
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x1018
        ),
    ]
}



/// while (i < 10) { sum += i; i++; }
pub fn example_with_loop() -> Vec<PcodeOp> {
    vec![
        // 0x2000: i = 0
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4), // RAX (i)
            Varnode::constant(0, 4),
            0x2000
        ),
        // 0x2004: sum = 0
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(8, 4), // RCX (sum)
            Varnode::constant(0, 4),
            0x2004
        ),
        
        // Loop header
        // 0x2008: temp = i < 10
        PcodeOp::binary(
            OpCode::IntSLess,
            Varnode::unique(100, 1),
            Varnode::register(0, 4),
            Varnode::constant(10, 4),
            0x2008
        ),
        
        // 0x200C: if (!temp) goto 0x2020 (exit)
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x2020, 8), Varnode::unique(100, 1)],
            0x200C
        ),
        
        // 0x2010: sum = sum + i
        PcodeOp::binary(
            OpCode::IntAdd,
            Varnode::register(8, 4),
            Varnode::register(8, 4),
            Varnode::register(0, 4),
            0x2010
        ),
        
        // 0x2014: i = i + 1
        PcodeOp::binary(
            OpCode::IntAdd,
            Varnode::register(0, 4),
            Varnode::register(0, 4),
            Varnode::constant(1, 4),
            0x2014
        ),
        
        // 0x2018: goto 0x2008
        PcodeOp::new(
            OpCode::Branch,
            None, 
            vec![Varnode::constant(0x2008, 8)],
            0x2018
        ),
        
        // Exit
        // 0x2020: return sum
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(8, 4)],
            0x2020
        ),
    ]
}



///
/// ```c
/// int switch_example(int x) {
///     switch (x) {
///         case 0:
///             return 10;
///         case 1:
///             return 20;
///         case 2:
///             return 30;
///         default:
///             return 0;
///     }
/// }
/// ```
pub fn example_with_switch() -> Vec<PcodeOp> {
    vec![
        // 0x3000: temp1 = x == 0
        PcodeOp::binary(
            OpCode::IntEqual,
            Varnode::unique(300, 1),
            Varnode::register(0, 4),   // x (RAX)
            Varnode::constant(0, 4),
            0x3000
        ),

        // 0x3004: if (temp1) goto 0x3020 (case 0)
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x3020, 8), Varnode::unique(300, 1)],
            0x3004
        ),

        // 0x3008: temp2 = x == 1
        PcodeOp::binary(
            OpCode::IntEqual,
            Varnode::unique(301, 1),
            Varnode::register(0, 4),
            Varnode::constant(1, 4),
            0x3008
        ),

        // 0x300C: if (temp2) goto 0x3028 (case 1)
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x3028, 8), Varnode::unique(301, 1)],
            0x300C
        ),

        // 0x3010: temp3 = x == 2
        PcodeOp::binary(
            OpCode::IntEqual,
            Varnode::unique(302, 1),
            Varnode::register(0, 4),
            Varnode::constant(2, 4),
            0x3010
        ),

        // 0x3014: if (temp3) goto 0x3030 (case 2)
        PcodeOp::new(
            OpCode::CBranch,
            None,
            vec![Varnode::constant(0x3030, 8), Varnode::unique(302, 1)],
            0x3014
        ),

        // 0x3018: goto 0x3038 (default)
        PcodeOp::new(
            OpCode::Branch,
            None,
            vec![Varnode::constant(0x3038, 8)],
            0x3018
        ),

        // 0x3020: return 10 (case 0)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::constant(10, 4),
            0x3020
        ),
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x3024
        ),

        // 0x3028: return 20 (case 1)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::constant(20, 4),
            0x3028
        ),
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x302C
        ),

        // 0x3030: return 30 (case 2)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::constant(30, 4),
            0x3030
        ),
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x3034
        ),

        // 0x3038: return 0 (default)
        PcodeOp::unary(
            OpCode::Copy,
            Varnode::register(0, 4),
            Varnode::constant(0, 4),
            0x3038
        ),
        PcodeOp::new(
            OpCode::Return,
            None,
            vec![Varnode::register(0, 4)],
            0x303C
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_translation_basic() {
        let pcodes = example_translation();
        assert_eq!(pcodes.len(), 7);
        assert_eq!(pcodes[0].opcode, OpCode::IntAdd);
        assert_eq!(pcodes[4].opcode, OpCode::Return);
    }

    #[test]
    fn test_example_with_loop() {
        let pcodes = example_with_loop();
        assert_eq!(pcodes.len(), 8);
        // check loop back
        assert_eq!(pcodes[6].opcode, OpCode::Branch);
    }

    #[test]
    fn test_example_with_switch() {
        let pcodes = example_with_switch();
        // switch contains multiple branches
        assert!(pcodes.len() > 10);
        // First comparison is IntEqual
        assert_eq!(pcodes[0].opcode, OpCode::IntEqual);
    }
}
