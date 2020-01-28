<?php
 session_start();
// //require_once("login.php");
 if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){

// 	//session_destroy();
 	header("location: welcome.php");
 	exit;
 }

	// include cofig File to connect with db
	require_once("config.php");
    //header('location: welcome.php');
	$username = $password = $confirm_password = "";
	$username_error = $password_error = $confirm_password_error = "";
	if ($_SERVER["REQUEST_METHOD"] == "POST") {
		// validate username 
		if(empty(trim($_POST["username"]))){
			$username_error = "Enter a username";
		}else{
			$sql = "SELECT id FROM loginapp WHERE username = ?";
			if($stmt = mysqli_prepare($link, $sql)){
				mysqli_stmt_bind_param($stmt, "s" , $param_username);
				$param_username = trim($_POST["username"]);
				if(mysqli_stmt_execute($stmt)){
					mysqli_stmt_store_result($stmt);	
					if(mysqli_stmt_num_rows($stmt) == 1){
						$username_error = "Username already Exist";
						//header("location:login.php")
					}else{
						$username = trim($_POST["username"]);
						echo $username;
					}
				    }else{
						echo "Oops Something Went Wrong";
					}
				}
			mysqli_stmt_close($stmt);
		}
		if(empty(trim($_POST["password"]))){
			$password_error = "please enter a password";
		}elseif(strlen(trim($_POST["password"])) < 6){
			$password_error = "Password must have 6 character long";
		}else{
			$password = trim($_POST["password"]);
			echo $password;
		}
		// validate confirm password
		if(empty(trim($_POST["confirm_password"]))){
			$confirm_password_error = "Please Confirm Pasword";
		}else{
			$confirm_password = trim($_POST["confirm_password"]);
			if(empty($password_error) && ($password !== $confirm_password)){
				$confirm_password_error = "Password did not match";
			}
		}
		if(empty($username_error) && empty($password_error) && empty($confirm_password_error)){
			$sql = "INSERT INTO loginapp (username, password) VALUES (?, ?)";
			if($stmt =mysqli_prepare($link, $sql)){
				mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
				$param_username = $username;
				//create a hash password
				$param_password = password_hash($password, PASSWORD_DEFAULT);
				if(mysqli_stmt_execute($stmt)){
					header("location:login.php");
				}else{
					echo "Something Went Wrong. Please Try Again later ";
				}		
			}
			// close statement
			mysqli_stmt_close($stmt);
		}
		// close connection
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
    <!-- <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>  -->
	<title>Sign In</title>
</head>
	<body>
			<div class="container">
				<h1 class="text-center">User Registration Form</h1>
				<form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" class="myform">
				<div class="form-row">
				    <div class="form-group<?php echo (!empty($username_error)) ? 'has-error' : ''; ?>">
				      <label for="Email">Email</label>
				      <input type="text" class="form-control" id="username" name="username" value="<?php echo $username; ?>">
				      <span class="help-block"><?php echo $username_error; ?></span>
				    </div>
				    <div class="form-group<?php echo (!empty($password_error)) ? 'has-error' : ''; ?>">
				      <label for="password">Password</label>
				      <input type="password" class="form-control" name="password" value="<?php echo $password; ?>">
				      <span class="help-block"><?php echo $password_error; ?></span>
				    </div>
				     <div class="form-group <?php echo (!empty($confirm_password_error)) ? 'has-error' : ''; ?>">
				      <label for="confrim_password">Confirm Password</label>
				      <input type="password" class="form-control"  name="confirm_password" value="<?php echo $confirm_password; ?>">
				      <span class="help-block"><?php echo $confirm_password_error; ?>
				    </div>
				</div>
				<div class="form-group form-row" id="submit-group">
                	<input type="submit" class="btn btn-success" id="submit" value="Submit">
                	<input type="reset" class="btn btn-primary" value="Reset">
            	</div>
            		<p id="login-group">Already have an account? <a href="login.php">Login here</a>.</p>
				</form>
			</div>
		<script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
		<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
		<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
		<!-- <script type="text/javascript"> 
              $(document).ready(function() 
               {     
              $("#submit").click(function(event) 
               {             
                event.preventDefault(); 
                alert("ACTION IS PREVENTED"); 
                }); 
                }); 
            </script> -->
	</body>
</html>