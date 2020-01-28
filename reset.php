<?php
	// initilize tht session
		session_start();
	if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
		header("location: login.php");
		exit;
	}
	//include config file
	require_once("config.php");
	$new_password = $confirm_password = "";
	$new_password_error = $confirm_password_error = "";
	if($_SERVER["REQUEST_METHOD"] == "POST"){
		if(empty(trim($_POST["new_password"]))){
			$new_password_error = "Please enter new password";
		} elseif(strlen(trim($_POST["new_password"])) < 6){
			$new_password_error = "Password must have 6 character long" ;
		}else{
			$new_password = trim($_POST["new_password"]);
		}
		//validate confirm password
		if(empty(trim($_POST["confirm_password"]))){
			$confirm_password_error = "Please confirm the password";
		}else{
			$confirm_password = trim($_POST["confirm_password"]);
			// please verify from senior $new_password!== $confirm_password
			if(empty($new_password_error) && $new_password != $confirm_password){
				$confirm_password_error = "Password did match";
			}
		}
		// check input errors before adding to the database
		if(empty($new_password_error) && empty($confirm_password_error)){
			// prepare update statement
			$sql = "UPDATE loginapp SET password = ? WHERE id = ?";
			if($stmt = mysqli_prepare($link,$sql)){
				mysqli_stmt_bind_param($stmt, "si" , $param_password , $param_id);
				// set parameters
				$param_password = password_hash($new_password, PASSWORD_DEFAULT);
				$param_id = $_SESSION["id"];

				//Attempt to execute the prepare statement
				if(mysqli_stmt_execute($stmt)){
					// password updated successfully Destroy the session and redirect to login page
					//echo "Password updated successfully";
					session_destroy();
					header("location: login.php");
					exit(); 
				}else{
					echo "Something Went Wrong! Please try again later";
				} 
			}
			// Close statement
			mysqli_stmt_close($stmt);
		}
		// Close Connection
		mysqli_close($link);
	}
?>
<!DOCTYPE html>
<html>
	<head>
		<title>Reset</title>
		<meta charset="utf-8">
	    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">	
	    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
	    <link rel="stylesheet" type="text/css" href="register.css">
	</head>
	<body>
		<div class="container">
			<h2 class="text-center">Reset Password</h2>
			<p class="text-center">Please Fill out this form to reset your passoword</p>
			<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
				<div class="form-group reset-group <?php echo(!empty($new_password_error)) ? 'has-error' : '' ?>">
					<label for="new_password">New Password</label>
					<input type="password" name="new_password" class="form-control" value="<?php echo $new_password; ?>">
					<span class="help-block"><?php echo $new_password_error; ?></span>
				</div>
				<div class="form-group reset-group <?php echo(!empty($confirm_password_error)) ? 'has-error' : '' ?>">
					<label for="confirm_password">Confirm Password</label>
					<input type="password" name="confirm_password" class="form-control" value="<?php echo $confirm_password; ?>">
					<span class="help-block"><?php echo $confirm_password_error; ?></span>
				</div>
				<div class="form-group reset-group">
	        <input type="submit" class="btn btn-primary" value="Submit">
	        <a class="btn btn-link" href="welcome.php">Cancel</a>
	      </div>
			</form>
		</div>
		<script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
		<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
		<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
	</body>
</html>