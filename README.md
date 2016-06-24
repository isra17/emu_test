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

---------------------------------------------------------------------------------------- benchmark: 8 tests ----------------------------------------------------------------------------------------
Name (time in us)                Min                     Max                    Mean                 StdDev                  Median                   IQR            Outliers(*)  Rounds  Iterations
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
test_miasm_gcc_1            124.9313 (1.0)          154.0184 (1.0)          127.4096 (1.0)           3.5500 (1.0)          126.8387 (1.0)          0.9537 (1.0)              4;6      76           1
test_miasm_gcc_2            334.0244 (2.67)         395.0596 (2.57)         347.8050 (2.73)         26.5194 (7.47)         334.9781 (2.64)        19.0139 (19.94)            1;1       5           1
test_unicorn_1              395.0596 (3.16)         503.7785 (3.27)         401.2671 (3.15)          5.6383 (1.59)         400.0664 (3.15)         2.1458 (2.25)           45;69    2025           1
test_vivisect_1           1,213.0737 (9.71)       1,635.0746 (10.62)      1,527.2174 (11.99)       134.4586 (37.88)      1,590.0135 (12.54)       10.9673 (11.50)          77;87     425           1
test_unicorn_2            1,428.8425 (11.44)      1,685.8578 (10.95)      1,448.0190 (11.37)        17.8884 (5.04)       1,446.0087 (11.40)        7.8678 (8.25)           28;30     602           1
test_miasm_python_1     109,492.0635 (876.42)   110,553.0262 (717.79)   109,835.6545 (862.07)      361.1920 (101.74)   109,713.0775 (864.98)     411.1528 (431.12)           2;0       8           1
test_vivisect_2         125,926.0178 (>1000.0)  126,734.0183 (822.85)   126,335.9785 (991.57)      375.2138 (105.69)   126,338.0051 (996.05)     703.9309 (738.12)           4;0       8           1
test_angr_1             130,347.9671 (>1000.0)  170,953.9890 (>1000.0)  136,975.8333 (>1000.0)  15,001.7200 (>1000.0)  131,417.9897 (>1000.0)  1,648.3665 (>1000.0)          1;1       7           1
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

(*) Outliers: 1 Standard Deviation from Mean; 1.5 IQR (InterQuartile Range) from 1st Quartile and 3rd Quartile.
=========================== 8 passed in 9.23 seconds ===========================
```
