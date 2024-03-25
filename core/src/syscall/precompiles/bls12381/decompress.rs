use crate::air::BaseAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::air::WORD_SIZE;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryReadWriteCols;
use crate::operations::field::field_op::FieldOpCols48;
use crate::operations::field::field_op::FieldOperation;
use crate::operations::field::field_sqrt::FieldSqrtCols48;
use crate::operations::field::params::Limbs;
use crate::runtime::ExecutionRecord;
use crate::runtime::MemoryReadRecord;
use crate::runtime::MemoryWriteRecord;
use crate::runtime::Syscall;
use crate::syscall::precompiles::SyscallContext;
use crate::utils::bytes_to_words_le;
use crate::utils::ec::field::FieldParameters;
use crate::utils::ec::weierstrass::bls12_381;
use crate::utils::ec::weierstrass::bls12_381::bls381_sqrt;
use crate::utils::ec::weierstrass::bls12_381::Bls12381BaseField;
use crate::utils::ec::weierstrass::bls12_381::Bls12381Parameters;
use crate::utils::ec::weierstrass::WeierstrassParameters;
use crate::utils::limbs_from_access;
use crate::utils::limbs_from_prev_access;
use crate::utils::pad_rows;
use crate::utils::words_to_bytes_le;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use num::BigUint;
use num::Zero;
use p3_air::{Air, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::MatrixRowSlices;
use serde::Deserializer;
use serde::Serializer;
use serde::{Deserialize, Serialize};

use p3_matrix::dense::RowMajorMatrix;
use sp1_derive::AlignedBorrow;
use std::fmt::Debug;

pub const NUM_WORDS_FIELD_ELEMENT: usize = 12;
pub const NUM_BYTES_FIELD_ELEMENT: usize = NUM_WORDS_FIELD_ELEMENT * WORD_SIZE;
pub const COMPRESSED_POINT_BYTES: usize = 48;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bls12381DecompressEvent {
    pub shard: u32,
    pub clk: u32,
    pub ptr: u32,
    pub sign: bool,
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    pub x_bytes: [u8; COMPRESSED_POINT_BYTES],
    #[serde(serialize_with = "to_hex", deserialize_with = "from_hex")]
    pub decompressed_y_bytes: [u8; NUM_BYTES_FIELD_ELEMENT],
    pub x_memory_records: [MemoryReadRecord; NUM_WORDS_FIELD_ELEMENT],
    pub y_memory_records: [MemoryWriteRecord; NUM_WORDS_FIELD_ELEMENT],
}

fn to_hex<T, S>(v: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(v.as_ref()))
}

fn from_hex<'de, D>(deserializer: D) -> std::result::Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: String = Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(bytes).unwrap();
    Ok(bytes.try_into().unwrap())
}

pub const NUM_BLS_DECOMPRESS_COLS: usize = size_of::<Bls12381DecompressCols<u8>>();
const NUM_LIMBS: usize = 48;

/// A chip that computes `BlsDecompress` given a pointer to a 16 word slice formatted as such:
/// input[0] is the sign bit. The second half of the slice is the compressed X in little endian.
///
/// After `BlsDecompress`, the first 32 bytes of the slice are overwritten with the decompressed Y.
#[derive(Default)]
pub struct Bls12381DecompressChip;

impl Bls12381DecompressChip {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for Bls12381DecompressChip {
    fn num_extra_cycles(&self) -> u32 {
        4
    }

    fn execute(&self, rt: &mut SyscallContext) -> u32 {
        let a0 = crate::runtime::Register::X10;

        let start_clk = rt.clk;

        // TODO: this will have to be be constrained, but can do it later.
        let slice_ptr = rt.register_unsafe(a0);
        if slice_ptr % 4 != 0 {
            panic!();
        }

        let (x_memory_records_vec, x_vec) = rt.mr_slice(
            slice_ptr + (COMPRESSED_POINT_BYTES as u32),
            NUM_WORDS_FIELD_ELEMENT,
        );
        let x_memory_records: [MemoryReadRecord; NUM_WORDS_FIELD_ELEMENT] =
            x_memory_records_vec.try_into().unwrap();

        // This unsafe read is okay because we do mw_slice into the first 12 words later.
        let sign = rt.byte_unsafe(slice_ptr + (COMPRESSED_POINT_BYTES as u32) - 1);
        let sign_bool = sign != 0;

        let x_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&x_vec);
        let mut g1_bytes_be = x_bytes;
        g1_bytes_be.reverse();
        // Re-insert sign into first byte of X for the requred compressed format
        g1_bytes_be[0] |= sign;

        let decompressed_point = bls12_381::decompress(&g1_bytes_be);

        let decompressed_point_bytes = decompressed_point.y.to_bytes_be();
        let mut decompressed_y_bytes = [0_u8; NUM_BYTES_FIELD_ELEMENT];
        decompressed_y_bytes.copy_from_slice(&decompressed_point_bytes);
        decompressed_y_bytes.reverse();
        let y_words: [u32; NUM_WORDS_FIELD_ELEMENT] = bytes_to_words_le(&decompressed_y_bytes);

        let y_memory_records_vec = rt.mw_slice(slice_ptr, &y_words);
        let y_memory_records: [MemoryWriteRecord; NUM_WORDS_FIELD_ELEMENT] =
            y_memory_records_vec.try_into().unwrap();

        let shard = rt.current_shard();
        rt.record_mut()
            .bls12381_decompress_events
            .push(Bls12381DecompressEvent {
                shard,
                clk: start_clk,
                ptr: slice_ptr,
                sign: sign_bool,
                x_bytes,
                decompressed_y_bytes,
                x_memory_records,
                y_memory_records,
            });

        rt.clk += 4;

        slice_ptr
    }
}

#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct Bls12381DecompressCols<T> {
    pub is_real: T,
    pub shard: T,
    pub clk: T,
    pub ptr: T,
    pub x_access: [MemoryReadCols<T>; NUM_WORDS_FIELD_ELEMENT],
    pub y_access: [MemoryReadWriteCols<T>; NUM_WORDS_FIELD_ELEMENT],
    pub(crate) x_2: FieldOpCols48<T>,
    pub(crate) x_3: FieldOpCols48<T>,
    pub(crate) x_3_plus_b: FieldOpCols48<T>,
    pub(crate) y: FieldSqrtCols48<T>,
    pub(crate) neg_y: FieldOpCols48<T>,
}

impl<F: PrimeField32> Bls12381DecompressCols<F> {
    pub fn populate(&mut self, event: Bls12381DecompressEvent, record: &mut ExecutionRecord) {
        let mut new_field_events = Vec::new();
        self.is_real = F::from_bool(true);
        self.shard = F::from_canonical_u32(event.shard);
        self.clk = F::from_canonical_u32(event.clk);
        self.ptr = F::from_canonical_u32(event.ptr);
        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            self.x_access[i].populate(event.x_memory_records[i], &mut new_field_events);
            self.y_access[i].populate_write(event.y_memory_records[i], &mut new_field_events);
        }

        let x = &BigUint::from_bytes_le(&event.x_bytes);
        self.populate_field_ops(x);

        record.add_field_events(&new_field_events);
    }

    fn populate_field_ops(&mut self, x: &BigUint) {
        // Y = sqrt(x^3 + b)
        let x_2 =
            self.x_2
                .populate::<Bls12381BaseField>(&x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = self
            .x_3
            .populate::<Bls12381BaseField>(&x_2, x, FieldOperation::Mul);
        let b = Bls12381Parameters::b_int();
        let x_3_plus_b =
            self.x_3_plus_b
                .populate::<Bls12381BaseField>(&x_3, &b, FieldOperation::Add);
        let y = self
            .y
            .populate::<Bls12381BaseField>(&x_3_plus_b, bls381_sqrt);
        let zero = BigUint::zero();
        self.neg_y
            .populate::<Bls12381BaseField>(&zero, &y, FieldOperation::Sub);
    }
}

impl<V: Copy> Bls12381DecompressCols<V> {
    pub fn eval<AB: SP1AirBuilder<Var = V>>(&self, builder: &mut AB)
    where
        V: Into<AB::Expr>,
    {
        let sign: AB::Expr =
            self.y_access[NUM_WORDS_FIELD_ELEMENT - 1].prev_value[WORD_SIZE - 1].into();
        builder.assert_bool(sign.clone());

        let x: Limbs<V, NUM_LIMBS> = limbs_from_prev_access(&self.x_access);
        self.x_2
            .eval::<AB, Bls12381BaseField, _, _>(builder, &x, &x, FieldOperation::Mul);
        self.x_3.eval::<AB, Bls12381BaseField, _, _>(
            builder,
            &self.x_2.result,
            &x,
            FieldOperation::Mul,
        );
        let b = Bls12381Parameters::b_int();
        let b_const = Bls12381BaseField::to_limbs_field::<AB::F, NUM_LIMBS>(&b);
        self.x_3_plus_b.eval::<AB, Bls12381BaseField, _, _>(
            builder,
            &self.x_3.result,
            &b_const,
            FieldOperation::Add,
        );
        self.y
            .eval::<AB, Bls12381BaseField>(builder, &self.x_3_plus_b.result);
        self.neg_y.eval::<AB, Bls12381BaseField, _, _>(
            builder,
            &[AB::Expr::zero()].iter(),
            &self.y.multiplication.result,
            FieldOperation::Sub,
        );

        let y_limbs: Limbs<V, NUM_LIMBS> = limbs_from_access(&self.y_access);
        builder
            .when(self.is_real)
            .assert_all_eq(self.y.multiplication.result, y_limbs);
        builder
            .when(self.is_real)
            .assert_all_eq(self.neg_y.result, y_limbs);

        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            builder.constraint_memory_access(
                self.shard,
                self.clk,
                self.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4 + 32),
                &self.x_access[i],
                self.is_real,
            );
        }
        for i in 0..NUM_WORDS_FIELD_ELEMENT {
            builder.constraint_memory_access(
                self.shard,
                self.clk,
                self.ptr.into() + AB::F::from_canonical_u32((i as u32) * 4),
                &self.y_access[i],
                self.is_real,
            );
        }
    }
}

impl<F: PrimeField32> MachineAir<F> for Bls12381DecompressChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "BlsDecompress".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for i in 0..input.bls12381_decompress_events.len() {
            let event = input.bls12381_decompress_events[i].clone();
            let mut row = [F::zero(); NUM_BLS_DECOMPRESS_COLS];
            let cols: &mut Bls12381DecompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate(event.clone(), output);

            rows.push(row);
        }

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_BLS_DECOMPRESS_COLS];
            let cols: &mut Bls12381DecompressCols<F> = row.as_mut_slice().borrow_mut();
            let zero = BigUint::zero();
            cols.populate_field_ops(&zero);
            row
        });

        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BLS_DECOMPRESS_COLS,
        )
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.bls12381_decompress_events.is_empty()
    }
}

impl<F> BaseAir<F> for Bls12381DecompressChip {
    fn width(&self) -> usize {
        NUM_BLS_DECOMPRESS_COLS
    }
}

impl<AB> Air<AB> for Bls12381DecompressChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row: &Bls12381DecompressCols<AB::Var> = main.row_slice(0).borrow();
        row.eval::<AB>(builder);
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        utils::{self, tests::BLS_DECOMPRESS_ELF},
        SP1Prover, SP1Stdin,
    };

    #[test]
    fn test_bls_decompress() {
        utils::setup_logger();
        SP1Prover::prove(BLS_DECOMPRESS_ELF, SP1Stdin::new()).unwrap();
    }
}
