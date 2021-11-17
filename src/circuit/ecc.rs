use crate::rns::{Integer, Rns};

use super::{integer::IntegerConfig, AssignedInteger};
use crate::circuit::integer::IntegerChip;
use halo2::arithmetic::{CurveAffine, FieldExt};
use halo2::circuit::Region;
use halo2::plonk::Error;
use num_bigint::BigUint as big_uint;

#[derive(Clone)]
pub struct IncompletePoint<'a, W: WrongExt, N: FieldExt> {
    x: Integer<'a, W, N>,
    y: Integer<'a, W, N>,
}

/// E is emulated curve, C is the native curve
impl<C: CurveAffine> Point<C> {
    pub fn new_from_point<E: CurveAffine>(p: E, num_of_limbs: usize, bit_len: usize) -> Self {
        let (_x, _y) = p
            .coordinates()
            .map(|p| -> (big_uint, big_uint) {
                let x = num_bigint::BigUint::from_bytes_le(&p.x().to_bytes());
                let y = num_bigint::BigUint::from_bytes_le(&p.y().to_bytes());
                (x, y)
            })
            .unwrap();

        let x = Integer::<C::ScalarExt>::from_big(_x, num_of_limbs, bit_len);
        let y = Integer::<C::ScalarExt>::from_big(_y, num_of_limbs, bit_len);
        Self { x, y }
    }
}

impl<C: CurveAffine> Point<C> {
    pub fn new(x: Integer<C::ScalarExt>, y: Integer<C::ScalarExt>) -> Self {
        Point { x, y }
    }
}

#[derive(Debug, Clone)]
pub struct AssignedPoint<C: CurveAffine> {
    pub x: AssignedInteger<C::ScalarExt>,
    pub y: AssignedInteger<C::ScalarExt>,
}

/// Linear combination term
pub enum Term<C: CurveAffine> {
    Assigned(AssignedPoint<C>, AssignedInteger<C::ScalarExt>),
    Unassigned(Option<Point<C>>, AssignedInteger<C::ScalarExt>),
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
    // indicate whether the poinit is the identity point of curve or not
    z: AssignedCondition<N>,
}

impl<N: FieldExt> AssignedPoint<N> {
    fn from_impcomplete(point: &AssignedIncompletePoint<N>, flag: &AssignedCondition<N>) -> Self {
        Self {
            x: point.x.clone(),
            y: point.y.clone(),
            z: flag.clone(),
        }
    }
}

#[derive(Clone, Debug)]
/// point that is assumed to be on curve and not infinity
pub struct AssignedIncompletePoint<N: FieldExt> {
    x: AssignedInteger<N>,
    y: AssignedInteger<N>,
}

impl<N: FieldExt> From<&AssignedPoint<N>> for AssignedIncompletePoint<N> {
    fn from(point: &AssignedPoint<N>) -> Self {
        AssignedIncompletePoint {
            x: point.x.clone(),
            y: point.y.clone(),
        }
    }
}

impl<F: FieldExt> AssignedPoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>, z: AssignedCondition<F>) -> AssignedPoint<F> {
        AssignedPoint { x, y, z }
    }

    pub fn is_identity(&self) -> AssignedCondition<F> {
        self.z.clone()
    }
}

impl<F: FieldExt> AssignedIncompletePoint<F> {
    pub fn new(x: AssignedInteger<F>, y: AssignedInteger<F>) -> AssignedIncompletePoint<F> {
        AssignedIncompletePoint { x, y }
    }
}

mod base_field_ecc;
mod general_ecc;

#[derive(Clone, Debug)]
pub struct EccConfig {
    range_config: RangeConfig,
    main_gate_config: MainGateConfig,
}

/// E is the emulated curve, C is the native curve
pub struct EccChip<E: CurveAffine, C: CurveAffine> {
    config: EccConfig,
    pub e_base_field: IntegerChip<E::Base, C::ScalarExt>,
    // e_scalar_field: IntegerChip<E::ScalarExt, C::ScalarExt>
}

pub trait EccInstruction<E: CurveAffine, C: CurveAffine> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Option<Point<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error>;
    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error>;
    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: E, e: AssignedInteger<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error>;
}

impl<E: CurveAffine, C: CurveAffine> EccInstruction<E, C> for EccChip<E, C> {
    fn assign_point(&self, region: &mut Region<'_, C::ScalarExt>, point: Option<Point<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn assert_is_on_curve(&self, region: &mut Region<'_, C::ScalarExt>, point: AssignedPoint<C>, offset: &mut usize) -> Result<(), Error> {
        unimplemented!();
    }

    fn assert_equal(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p0: AssignedPoint<C>,
        p1: AssignedPoint<C>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn add(&self, region: &mut Region<'_, C::ScalarExt>, p0: AssignedPoint<C>, p1: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn double(&self, region: &mut Region<'_, C::ScalarExt>, p: AssignedPoint<C>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_var(
        &self,
        region: &mut Region<'_, C::ScalarExt>,
        p: AssignedPoint<C>,
        e: AssignedInteger<C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn mul_fix(&self, region: &mut Region<'_, C::ScalarExt>, p: E, e: AssignedInteger<C::ScalarExt>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn multi_exp(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }

    fn combine(&self, region: &mut Region<'_, C::ScalarExt>, terms: Vec<Term<C>>, u: C::ScalarExt, offset: &mut usize) -> Result<AssignedPoint<C>, Error> {
        unimplemented!();
    }
}
