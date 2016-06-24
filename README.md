# Emulation Tests
This repo contains some tests to benchmark four differents emulation frameworks. The tests emule `strcmp` and `sha256`, although some frameworks are not tested against `sha256` since it is too slow. It is important to note that the author had no previous experience with those framework and some key part might be missing to get better performances. Some framework also provide much more functionnalities than emulation and this simple benchmark does not reflect this.

The benchmarked frameworks are:
 * [Angr](http://angr.io/)
 * [Miasm](https://github.com/cea-sec/miasm)
 * [Unicorn](http://www.unicorn-engine.org/)
 * [Vivisect](https://github.com/vivisect/vivisect)

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
```

### strcmp
```
------------------------------------------------------------------------------------------- benchmark: 5 tests ------------------------------------------------------------------------------------------
Name (time in us)                     Min                     Max                    Mean                 StdDev                  Median                   IQR            Outliers(*)  Rounds  Iterations
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_miasm_gcc_strcmp            125.8850 (1.0)          153.0647 (1.0)          128.8350 (1.0)           3.3783 (1.0)          128.0308 (1.0)          1.7285 (1.0)              5;6      75           1
test_unicorn_strcmp              393.8675 (3.13)         481.1287 (3.14)         403.7474 (3.13)          5.4744 (1.62)         402.9274 (3.15)         2.8610 (1.66)         123;100    2017           1
test_vivisect_strcmp           1,216.8884 (9.67)       1,605.0339 (10.49)      1,490.2788 (11.57)       153.7369 (45.51)      1,588.8214 (12.41)      306.3679 (177.24)         115;0     425           1
test_miasm_python_strcmp     108,542.9192 (862.24)   110,633.1348 (722.79)   109,300.4942 (848.38)      773.8709 (229.07)   109,220.9816 (853.08)   1,205.0867 (697.17)           2;0       8           1
test_angr_strcmp             130,123.8537 (>1000.0)  169,132.9479 (>1000.0)  136,936.9711 (>1000.0)  14,245.4859 (>1000.0)  131,787.0617 (>1000.0)  2,479.6724 (>1000.0)          1;1       7           1
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

(*) Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
======================= 3 tests deselected by '-kstrcmp' =======================
==================== 5 passed, 3 deselected in 6.69 seconds ====================
```

### sha256
```
--------------------------------------------------------------------------------------- benchmark: 3 tests --------------------------------------------------------------------------------------
Name (time in us)                  Min                     Max                    Mean              StdDev                  Median                 IQR            Outliers(*)  Rounds  Iterations
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_miasm_gcc_sha256         324.0108 (1.0)          387.9070 (1.0)          337.9822 (1.0)       27.9853 (1.55)         324.9645 (1.0)       19.7291 (2.43)             1;1       5           1
test_unicorn_sha256         1,426.9352 (4.40)       1,721.1437 (4.44)       1,447.2362 (4.28)      18.0536 (1.0)        1,444.8166 (4.45)       8.1062 (1.0)            28;29     646           1
test_vivisect_sha256      125,589.1323 (387.61)   128,115.8924 (330.27)   126,339.1177 (373.80)   931.1174 (51.58)    126,080.3938 (387.98)   666.8568 (82.26)            1;1       6           1
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

(*) Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
======================= 5 tests deselected by '-ksha256' =======================
==================== 3 passed, 5 deselected in 4.50 seconds ====================
```
