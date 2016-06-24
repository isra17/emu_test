# Emulation Tests
This repo contains some tests to benchmark four differents emulation frameworks. The tests emule `strcmp` and `sha256`, although some frameworks are not tested against `sha256` since it is too slow. It is important to note that the author had no previous experience with those framework and some key part might be missing to get better performances. Some framework also provide much more functionnalities than emulation and this simple benchmark does not reflect this.

## Running the benchmark
Simply install all the dependancies and then run the benchmarks with pytest:

 * `pip install -r requirements.txt`
 * `py.test test_*`

## Benchmark Results
Running on ArchLinux x86-64, `Intel(R) Core(TM) i5-4670 CPU @ 3.40GHz` and `8 Go RAM`.

```
============================= test session starts ==============================
platform linux2 -- Python 2.7.11, pytest-2.9.1, py-1.4.31, pluggy-0.3.1
benchmark: 3.0.0 (defaults: timer=time.time disable_gc=False min_rounds=5 min_time=5.00us max_time=1.00s calibration_precision=10 warmup=False warmup_iterations=100000)
plugins: benchmark-3.0.0

------------------------------------------------------------------------------------------- benchmark: 8 tests ------------------------------------------------------------------------------------------
Name (time in us)                     Min                     Max                    Mean                 StdDev                  Median                   IQR            Outliers(*)  Rounds  Iterations
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_miasm_gcc_strcmp            126.8387 (1.0)          156.1642 (1.0)          128.7746 (1.0)           3.6786 (1.0)          128.0308 (1.0)          0.0000 (1.0)             4;33      75           1
test_miasm_gcc_sha256            329.0176 (2.59)         391.0065 (2.50)         344.8486 (2.68)         26.2426 (7.13)         333.0708 (2.60)        23.9015 (inf)              1;1       5           1
test_unicorn_strcmp              386.9534 (3.05)         717.1631 (4.59)         396.9796 (3.08)          9.4068 (2.56)         396.0133 (3.09)         3.0994 (inf)           40;105    2063           1
test_unicorn_sha256            1,429.0810 (11.27)      1,821.9948 (11.67)      1,450.1097 (11.26)        18.9602 (5.15)       1,448.1544 (11.31)        8.8215 (inf)            20;23     612           1
test_vivisect_strcmp           1,530.1704 (12.06)      1,769.0659 (11.33)      1,559.3476 (12.11)        18.0652 (4.91)       1,559.0191 (12.18)        6.1989 (inf)            46;61     421           1
test_miasm_python_strcmp     107,929.9450 (850.92)   113,962.8887 (729.76)   109,075.2482 (847.02)    2,021.2232 (549.46)   108,448.9822 (847.05)     972.5094 (inf)              1;1       8           1
test_vivisect_sha256         126,180.1720 (994.81)   127,100.9445 (813.89)   126,496.7322 (982.31)      321.0558 (87.28)    126,327.9915 (986.70)     411.5105 (inf)              2;0       8           1
test_angr_strcmp             130,481.0047 (>1000.0)  170,129.0607 (>1000.0)  138,369.6965 (>1000.0)  14,094.8246 (>1000.0)  134,091.1388 (>1000.0)  2,756.2976 (inf)              1;1       7           1
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

(*) Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
=========================== 8 passed in 9.28 seconds ===========================
```
