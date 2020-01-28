<?php
	$my_str = 'If the facts do not fit the theory, change the facts.';
 
	// Perform string replacement
	str_replace("facts", "truth", $my_str, $count);
	 
	// Display number of replacements performed
	echo "The text was replaced $count times.";
?>