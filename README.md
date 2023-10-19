# GradeSubmissionWithJWT


Documentation
Grade Submission
﻿

Student
﻿

POST
C
http://localhost:8080/student
﻿

Body
raw (json)
json
{
    "name":"Sushant",
    "birthDate":"2000-12-03"
}
GET
get 1
http://localhost:8080/student/2
﻿

Body
raw (json)
json
{
    "name":"Sushant",
    "birthDate":"2000-12-03"
}
GET
get all
http://localhost:8080/student/all
﻿

Body
raw (json)
json
{
    "name":"Sushant",
    "birthDate":"2000-12-03"
}
DELETE
delete
http://localhost:8080/student/1
﻿

GET
get enrolled courses
http://localhost:8080/student/1/course
﻿

Grade
﻿

POST
set
http://localhost:8080/grade/student/1/course/4
﻿

Body
raw (json)
json
{
    "score":"A+"
}
GET
read
http://localhost:8080/grade/student/1/course/1
﻿

DELETE
delete
http://localhost:8080/grade/student/1/course/4
﻿

GET
get student grades
﻿

GET
get coursewise grades
﻿

GET
read all
http://localhost:8080/grade/all
﻿

Course
﻿

POST
New request
http://localhost:8080/course
﻿

Body
raw (json)
json
{
    "subject": "Math",
    "code": "M6",
    "description": "Matrix  integration"
}
GET
get aol
http://localhost:8080/course/all
﻿

PUT
Enroll studen to course
http://localhost:8080/course/2/student/4
﻿

GET
get course student
﻿

User
﻿

POST
register user
http://localhost:8080/user/register
﻿

Body
raw (json)
json
{
    "username":"sushant",
    "password":"Sushant@123"
}
POST
New Request
http://localhost:8080/authenticate
﻿

Body
raw (json)
json
{
    "username":"sushant",
    "password":"Sushant@123"
}
GET
New request
http://localhost:8080/user/1
