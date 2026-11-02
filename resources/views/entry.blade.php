<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in</title></head>
<body>
<main>
    <h1>Sign in</h1>
    <form method="post" action="{{ $identity->url('login') }}">
        @csrf
        <button type="submit">Continue to sign in</button>
    </form>
</main>
</body>
</html>
