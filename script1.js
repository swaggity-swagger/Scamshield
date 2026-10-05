// Exp 4 - Patient Registration Validation

const form = document.getElementById("form");

if (form) {

    form.addEventListener("submit", function (e) {

        e.preventDefault();

        let valid = true;

        let name = document.getElementById("name").value.trim();
        let address = document.getElementById("address").value.trim();
        let mobile = document.getElementById("mobile").value.trim();
        let email = document.getElementById("email").value.trim();

        let gender = document.querySelector('input[name="gender"]:checked');
        let blood = document.getElementById("blood").value;
        let department = document.getElementById("department").value;
        let dob = document.getElementById("dob").value;
        let regDate = document.getElementById("regDate").value;

        let today = new Date().toISOString().split("T")[0];

        // Clear old errors

        document.getElementById("nameError").innerHTML = "";
        document.getElementById("addressError").innerHTML = "";
        document.getElementById("mobileError").innerHTML = "";
        document.getElementById("emailError").innerHTML = "";
        document.getElementById("genderError").innerHTML = "";
        document.getElementById("bloodError").innerHTML = "";
        document.getElementById("departmentError").innerHTML = "";
        document.getElementById("dobError").innerHTML = "";
        document.getElementById("dateError").innerHTML = "";

        document.getElementById("success").innerHTML = "";

        // Patient Name

        if (name == "") {

            document.getElementById("nameError").innerHTML =
                "Patient name is required";

            valid = false;

        }
        else if (!/^[A-Za-z ]+$/.test(name)) {

            document.getElementById("nameError").innerHTML =
                "Only alphabets and spaces allowed";

            valid = false;
        }


        // Address

        if (address == "") {

            document.getElementById("addressError").innerHTML =
                "Address is required";

            valid = false;
        }


        // Mobile Number

        if (!/^[6-9][0-9]{9}$/.test(mobile)) {

            document.getElementById("mobileError").innerHTML =
                "Enter valid 10-digit mobile number";

            valid = false;
        }


        // Email

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {

            document.getElementById("emailError").innerHTML =
                "Enter valid email";

            valid = false;
        }


        // Gender

        if (!gender) {

            document.getElementById("genderError").innerHTML =
                "Select gender";

            valid = false;
        }


        // Blood Group

        if (blood == "") {

            document.getElementById("bloodError").innerHTML =
                "Select blood group";

            valid = false;
        }


        // Department

        if (department == "") {

            document.getElementById("departmentError").innerHTML =
                "Select department";

            valid = false;
        }


        // Date of Birth

        if (dob == "" || dob > today) {

            document.getElementById("dobError").innerHTML =
                "Enter valid date of birth";

            valid = false;
        }


        // Registration Date

        if (regDate == "" || regDate > today) {

            document.getElementById("dateError").innerHTML =
                "Enter valid registration date";

            valid = false;
        }


        // If all details are valid

        if (valid) {

            document.getElementById("success").innerHTML =
                "Patient registered successfully!";

            console.log("Patient registration successful");

            // Exp 5 Task 1
            showRegistrationDetails(name);

            // Exp 5 Task 2
            showAppointmentPriority();

            // Exp 5 Task 3
            createPatientObject(name, mobile, gender.value, blood, department);

            // Exp 5 Task 4
            showAgeAnalysis();

            // Exp 5 Task 5
            validatePatientDetails(name, mobile, email);
        }

    });


    // Reset form

    form.addEventListener("reset", function () {

        document.getElementById("success").innerHTML = "";

        let errors = document.querySelectorAll(".error");

        errors.forEach(function (error) {
            error.innerHTML = "";
        });

    });

}


// Exp 5 Task 1
// Patient Information and Registration Fee Calculation

function showRegistrationDetails(name) {

    let patientName = name;
    let patientId = "PAT-1001";
    let age = 19;

    let consultationFee = 800;
    let registrationFee = 200;

    let total = consultationFee + registrationFee;

    let status;

    if (age >= 60) {

        status = "Senior citizen discount applicable";

    }
    else {

        status = "Regular registration";

    }

    console.log("Patient Name: " + patientName);
    console.log("Patient ID: " + patientId);
    console.log("Total Amount: Rs. " + total);
    console.log("Registration Status: " + status);

    alert("Patient Registration Completed");

    let output = document.getElementById("exp5Output");

    if (output) {

        output.innerHTML =
            "<h3>Registration Details</h3>" +
            "Patient Name: " + patientName + "<br>" +
            "Patient ID: " + patientId + "<br>" +
            "Total Amount: Rs. " + total + "<br>" +
            "Registration Status: " + status;

    }
}


// Exp 5 Task 2
// Appointment Priority

function showAppointmentPriority() {

    let patientAge = 65;
    let temperature = 38;
    let severity = "Moderate";
    let emergency = "Yes";

    let priority;

    if (emergency == "Yes") {

        priority = "Emergency Consultation Required";

    }
    else if (temperature >= 39) {

        priority = "High Priority Consultation";

    }
    else if (severity == "Severe") {

        priority = "High Priority Consultation";

    }
    else if (patientAge >= 60 && severity == "Moderate") {

        priority = "Priority Consultation";

    }
    else {

        priority = "Regular Consultation";

    }

    console.log("Appointment Priority: " + priority);

    let output = document.getElementById("priorityOutput");

    if (output) {

        output.innerHTML =
            "<h3>Appointment Priority</h3>" +
            priority;

    }
}


// Exp 5 Task 3
// Patient Object

function createPatientObject(name, mobile, gender, bloodGroup, department) {

    let patient = {

        patientName: name,

        patientId: "PAT-1001",

        age: 19,

        gender: gender,

        bloodGroup: bloodGroup,

        mobile: mobile,

        department: department,

        appointmentType: "Consultation",

        registrationStatus: "Confirmed",

        displayPatient: function () {

            return (
                "Patient Name: " + this.patientName + "<br>" +
                "Patient ID: " + this.patientId + "<br>" +
                "Age: " + this.age + "<br>" +
                "Gender: " + this.gender + "<br>" +
                "Blood Group: " + this.bloodGroup + "<br>" +
                "Mobile: " + this.mobile
            );

        },

        displayAppointment: function () {

            return (
                "Department: " + this.department + "<br>" +
                "Appointment Type: " + this.appointmentType + "<br>" +
                "Registration Status: " + this.registrationStatus
            );

        },

        checkAge: function () {

            if (this.age >= 60) {

                return "Patient is a senior citizen";

            }
            else if (this.age >= 18) {

                return "Patient is an adult";

            }
            else {

                return "Patient is a minor";

            }

        }

    };


    console.log(patient.displayPatient());
    console.log(patient.displayAppointment());
    console.log(patient.checkAge());


    let output = document.getElementById("patientOutput");

    if (output) {

        output.innerHTML =
            "<h3>Patient Information</h3>" +
            patient.displayPatient() +
            "<br><br>" +
            patient.displayAppointment() +
            "<br><br>" +
            patient.checkAge();

    }

}


// Exp 5 Task 4
// Patient Age Analysis

function showAgeAnalysis() {

    let patientAges = [22, 35, 67, 45, 29, 72, 56, 18, 64, 40];

    let minimum = patientAges[0];
    let maximum = patientAges[0];

    let totalAge = 0;
    let senior = 0;
    let below18 = 0;

    for (let i = 0; i < patientAges.length; i++) {

        if (patientAges[i] < minimum) {

            minimum = patientAges[i];

        }

        if (patientAges[i] > maximum) {

            maximum = patientAges[i];

        }

        totalAge = totalAge + patientAges[i];

        if (patientAges[i] >= 60) {

            senior++;

        }

        if (patientAges[i] < 18) {

            below18++;

        }

    }

    let average = totalAge / patientAges.length;

    let above60 = [];

    for (let i = 0; i < patientAges.length; i++) {

        if (patientAges[i] > 60) {

            above60.push(patientAges[i]);

        }

    }


    console.log("Patient Ages: " + patientAges);
    console.log("Minimum Age: " + minimum);
    console.log("Maximum Age: " + maximum);
    console.log("Average Age: " + average);
    console.log("Senior Citizens: " + senior);
    console.log("Below 18: " + below18);
    console.log("Age greater than 60: " + above60);


    let output = document.getElementById("ageOutput");

    if (output) {

        output.innerHTML =
            "<h3>Patient Age Analysis</h3>" +
            "Patient Ages: " + patientAges + "<br>" +
            "Minimum Age: " + minimum + "<br>" +
            "Maximum Age: " + maximum + "<br>" +
            "Average Age: " + average + "<br>" +
            "Senior Citizens: " + senior + "<br>" +
            "Below 18: " + below18 + "<br>" +
            "Age greater than 60: " + above60.join(" ");

    }

}


// Exp 5 Task 5
// Regular Expression Validation

function validatePatientDetails(name, mobile, email) {

    let patientId = "PAT-1234";

    let namePattern = /^[A-Za-z ]+$/;

    let mobilePattern = /^[0-9]{10}$/;

    let idPattern = /^PAT-[0-9]{4}$/;

    let emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    let nameValid = namePattern.test(name);

    let mobileValid = mobilePattern.test(mobile);

    let idValid = idPattern.test(patientId);

    let emailValid = emailPattern.test(email);


    console.log("Patient Name valid: " + nameValid);
    console.log("Mobile Number valid: " + mobileValid);
    console.log("Patient ID valid: " + idValid);
    console.log("Email valid: " + emailValid);


    let output = document.getElementById("regexOutput");

    if (output) {

        if (nameValid && mobileValid && idValid && emailValid) {

            output.innerHTML =
                "<h3>Registration Validation</h3>" +
                "Patient Name is valid<br>" +
                "Mobile Number is valid<br>" +
                "Patient ID is valid<br>" +
                "Email is valid<br><br>" +
                "All patient details are valid.";

        }
        else {

            output.innerHTML =
                "<h3>Registration Validation</h3>" +
                "Please check the patient registration details.";

        }

    }

}