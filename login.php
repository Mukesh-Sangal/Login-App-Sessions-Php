<?php
 session_start();
if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){

	//session_destroy();
	header("location: welcome.php");
	exit;
}
require_once("config.php");
// define variable with empty values
$username = $password = "";
$username_error = $password_error = "";
// process form with data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){
	//check if username is empty
	if(empty(trim($_POST['username']))){
		$username_error = "Please enter a username";
	}else{
		$username = trim($_POST["username"]);
	}
	// check if password is empty
	if(empty(trim($_POST["password"]))){
		$password_error = "Please Enter a password";
	}else{
		$password = trim($_POST["password"]);
	}
	// validate credential
	if(empty($username_error) && empty($password_error)){
		$sql = "SELECT id,username,password FROM loginapp WHERE username = ?";
		if($stmt = mysqli_prepare($link,$sql)){
			// bind variable to the prepend statement as parmeters
			mysqli_stmt_bind_param($stmt, "s", $param_username);
			// set parameter
			$param_username = $username;
			// Attempt to execute prepared statement
			if(mysqli_stmt_execute($stmt)){
				mysqli_stmt_store_result($stmt);
				//check is username is exist
				if(mysqli_stmt_num_rows($stmt) == 1){
					mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
					if(mysqli_stmt_fetch($stmt)){
						if(password_verify($password, $hashed_password)){
							session_start();
							$_SESSION["loggedin"] = true;
							$_SESSION["id"] = $id;
							$_SESSION["username"] = $username;
							// redirect to user to welcome page
							header("location: welcome.php");
						}else{
							// display the error message if the password is not correct
							$password_error = "the password you enter is not valid";
						}	
					}
				}else{
					// display username error when username doesn't exist
					$username_error = "No Account found With this username";
				}
			}
			else{
				echo "Oops something went wrong please Try again later";
			}
		}
		mysqli_stmt_close($stmt);
	}
	mysqli_close($link);
}
?>
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
    <link rel="stylesheet" type="text/css" href="register.css">
	<title>login</title>
</head>
<body>
	<div class="container">
		<h2 class="text-center">Login</h2>
		<p class="text-center">Please fill your credential to login</p>
		<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>" method="post">
			<div class="form-group <?php echo (!empty($username_error)) ? 'has-error' : ''; ?>" id="login-group">
                <label for="username">Username</label>
                <input type="text" name="username" class="form-control" value="<?php echo $username; ?>">
                <span class="help-block"><?php echo $username_error; ?></span>
            </div>    
            <div class="form-group <?php echo (!empty($password_error)) ? 'has-error' : ''; ?>" id="login-group">
            	<label for="password">Password</label>
            	<input type="password" name="password" class="form-control">
                <span class="help-block"><?php echo $password_error; ?></span>
            </div>
            <div class="form-group" id="login-group">
                <input type="submit" class="btn btn-primary" value="Login">
            </div>
            <p id="login-group">Don't have an account? <a href="register.php">Sign up now</a></p>
            <p id="login-group"><a href="reset.php">Reset Your Password</a></p>
		</form>
	</div>
	<script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
	<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
	<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
</body>
</html>