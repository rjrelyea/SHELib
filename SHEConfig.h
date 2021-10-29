//
// int Collect all the configuration parameters in one spt
//
#ifndef SHEConfig_H
#define SHEConfig_H_ 1

#define DEBUG 1
// values used as the default to decide if we need to 
// bootstrap before the next operation
#define SHEINT_DEFAULT_LEVEL_TRIGGER 80
// this should be a function we query from the context. It should be
// the capacity remaining after we complete a recrypt operation.
#define SHEINT_LEVEL_THRESHOLD 390
// the maximum size of the debugging label for temporaries which
// is outputted in the SHExxxSummary stream outputs
#define SHEINT_MAX_LABEL_SIZE 16
// maximum number of generators and orders in the context table
#define SHECONTEXT_MAX_GEN_SIZE 3
#define SHECONTEXT_MAX_ORD_SIZE 3
// SHEMATH_TRIG  number of tailor series for trig functions
// can't be > 36! or you need to update the tangent array
#define SHEMATH_TRIG_LOOP_COUNT 15
// number of tailor series for Natural log calculations
#define SHEMATH_LN_LOOP_COUNT 15

//////////////////////////////////////////////////////////////
// flags
//// /////////////////////////////////////////////////////////

// Use the table of pre defined contexts when selecting a context
#define SHECONTEXT_USE_TABLE 1

// use the CLZ builtin to figure out how many bits of we need to represent
// and integer
#define SHEFP_USE_CLZ_BUILTIN 1

// subraction compare is slower, but single bit operation compare
// uses more levels, and thus may take multiple bootstrapping operations.
// this option triggers using subtraction instead of single bit ops
//#define SHEINT_COMPARE_USE_SUB 1

//use long double as our basic floating point exchange (between encrypted
//and decrypted values) by default we use double. Using the smaller value
//means we can loose precision when creating or decrypting SHEFp values
//when using interal floating point times of types greater than double.
//#define SHEFP_ENABLE_LONG_DOUBLE 1

/////////////////////////////////////////////////////////
// Test Program flags and parameters
////////////////////////////////////////////////////////

// skip all division tests
//#define SHE_SKIP_DIV 1

// use half float instead of float in tests
//#define SHE_USE_HALF_FLOAT 1

// how squishy floating point diff can be before
// still testing as equal.
#ifdef SHE_USE_HALF_FLOAT
#define F_epsilon .003
#else
#define F_epsilon (1.5e-7)
#endif


#endif

