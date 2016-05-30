#include <cstring>
#include <iostream>
#include <map>
#include <string>

extern "C" {

int test_1() {
  std::map<std::string, int> map;
  map["a"] = 0;
  map["b"] = 1;
  map["c"] = 2;
  return map.find("c")->second;
}

int test_2() {
  int x;
  std::cin >> x;
  return x;
}

int test_3() {
  return strcmp((char*)1, (char*)2);
}

}

int main() {
  return 0;
}

