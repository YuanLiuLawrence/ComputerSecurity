#!/usr/bin/env python

#Fields.py

# Homework Number: 03
# Name: Yuan Liu
# ECN login: liu1827
# Due Date: 2/5/2020


def check_fields():
    # Let the user to input the number
    number = int(input('Number (smaller than 50):'))

    # Check the condition when number is 0 or 1
    if number == 0 or number == 1:
        return print("ring")
    # If the number is greater than 2
    else:
        # if the number is not prime then z_(number) is a ring
        for i in range(2, number):
            if number % i == 0:
                return print("ring")
    # if the number is prime then z_(number) is a field
    return print("field")


if __name__ == '__main__':
    check_fields()

