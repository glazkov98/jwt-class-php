# Class for working with JWT

## Example

```
//require JWT.php
require_once 'JWT.php';

//options for JWT instance
$options = [
	'secret' => 'YourSecretKey'
];

//mock data
$user = [
	'id' => 3,
	'name' => 'Admin',
	'role' => 'admin'
];

//create instance
$jwt = new JWT($options);

//create token
$token = $jwt->sign($user);

echo $token;
```