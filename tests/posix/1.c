#include <stdio.h>

void func2() { }

void func5() {}

void func4() {
	func5();
}

void func3() {
	func4();
}

void func1() {
	func2();
	func3();
}


int main()
{
		func1();
		func5();
}