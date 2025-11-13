<?php
// Simple XSS Vulnerable Application for Testing
?>
<!DOCTYPE html>
<html>
<head>
    <title>XSS Test Application</title>
</head>
<body>
    <h1>XSS Test Application</h1>
    
    <!-- Reflected XSS Vulnerability -->
    <h2>Search Form (Reflected XSS)</h2>
    <form method="GET">
        <input type="text" name="q" value="<?php echo $_GET['q'] ?? ''; ?>" placeholder="Search...">
        <input type="submit" value="Search">
    </form>
    
    <?php if (isset($_GET['q'])): ?>
        <p>You searched for: <?php echo $_GET['q']; ?></p>
    <?php endif; ?>
    
    <!-- Another vulnerable parameter -->
    <h2>User Profile (Reflected XSS)</h2>
    <form method="GET">
        <input type="text" name="name" value="<?php echo $_GET['name'] ?? ''; ?>" placeholder="Your name...">
        <input type="text" name="email" value="<?php echo $_GET['email'] ?? ''; ?>" placeholder="Your email...">
        <input type="submit" value="Update">
    </form>
    
    <?php if (isset($_GET['name']) || isset($_GET['email'])): ?>
        <div>
            <?php if (isset($_GET['name'])): ?>
                <p>Name: <?php echo $_GET['name']; ?></p>
            <?php endif; ?>
            <?php if (isset($_GET['email'])): ?>
                <p>Email: <?php echo $_GET['email']; ?></p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    
</body>
</html>