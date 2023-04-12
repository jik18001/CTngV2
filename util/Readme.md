# Utility Functions

Dependency cycles are not allowed in go. Therefore, sometimes as individual packages become very large, we arrive at a cycle of dependencies, despite most of these packages not being utilized.

Any helper functions/code that doesn't import anything in packages can go into into this util package,
which should not import any other packages.

## Code Owners:
- Jie: Created IO.go and inner-functions.
- Finn: Types.go and color character constants.

##### Written By Finn