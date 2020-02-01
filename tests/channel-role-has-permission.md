|let *p* be "higher-scoped scheme has the permission" |let *q* be "the permission is moderated"	|let *r* be "channel scheme has the permission"	|compound statement for "channel role has the permission"|
|--|--|--|--|
|*p*	|*q*	|*r*	|*p*∧(*q*→*r*)|
|TRUE|	TRUE|	TRUE|	TRUE|
|TRUE|	TRUE|	FALSE|	FALSE|
|TRUE|	FALSE|	TRUE|	TRUE|
|TRUE|	FALSE|	FALSE|	TRUE|
|FALSE|	TRUE|	TRUE|	FALSE|
|FALSE|	TRUE|	FALSE|	FALSE|
|FALSE|	FALSE|	TRUE|	FALSE|
|FALSE|	FALSE|	FALSE|	FALSE|

See https://play.golang.org/p/BmolzitEEdk for an example implementation of the logic for *p*∧(*q*→*r*).