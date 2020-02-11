|let *p* be "higher-scoped scheme has the permission" |let *q* be "the permission is moderated"	|let *r* be "channel scheme has the permission"|let *s* be "channel role is `channel_admin`" 	|compound statement for "channel role has the permission"|
|--|--|--|--|--|
|*p*	|*q*	|*r*|	*s*|*p* ∧ (*s* ∨ (*q* → *r*))|
|TRUE|	TRUE|	TRUE|	TRUE|	TRUE|
|TRUE|	TRUE|	TRUE|	FALSE|	TRUE|
|TRUE|	TRUE|	FALSE|	TRUE|	TRUE|
|TRUE|	TRUE|	FALSE|	FALSE|	FALSE|
|TRUE|	FALSE|	TRUE|	TRUE|	TRUE|
|TRUE|	FALSE|	TRUE|	FALSE|	TRUE|
|TRUE|	FALSE|	FALSE|	TRUE|	TRUE|
|TRUE|	FALSE|	FALSE|	FALSE|	TRUE|
|FALSE|	TRUE|	TRUE|	TRUE|	FALSE|
|FALSE|	TRUE|	TRUE|	FALSE|	FALSE|
|FALSE|	TRUE|	FALSE|	TRUE|	FALSE|
|FALSE|	TRUE|	FALSE|	FALSE|	FALSE|
|FALSE|	FALSE|	TRUE|	TRUE|	FALSE|
|FALSE|	FALSE|	TRUE|	FALSE|	FALSE|
|FALSE|	FALSE|	FALSE|	TRUE|	FALSE|

See https://play.golang.org/p/8jskjSkVt34 for an example implementation of the logic for *p* ∧ (*s* ∨ (*q* → *r*)).