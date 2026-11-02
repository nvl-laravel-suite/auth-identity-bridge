<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Choose access</title>
<style>body{font:16px/1.5 system-ui;background:#f5f5f5;color:#171717;margin:0}main{max-width:42rem;margin:8vh auto;padding:2rem}h1{font-size:1.75rem}form{background:white;border:1px solid #ddd;border-radius:12px;padding:1.25rem;margin:1rem 0}button{font:inherit;padding:.65rem 1rem;border:1px solid #ccc;border-radius:8px;background:#171717;color:white;cursor:pointer}p{color:#555}</style></head>
<body><main><h1>Choose your access</h1><p>Select the organization and role for this session.</p>
@forelse($contexts['contexts'] as $context)
<form method="post" action="{{ $identity->url('context.select') }}">@csrf
<input type="hidden" name="context_version" value="{{ $contexts['local_context_version'] }}">
@foreach($context['selection'] as $key => $value)<input type="hidden" name="{{ $key }}" value="{{ $value }}">@endforeach
<strong>{{ $context['applicationName'] }}</strong><p>{{ $context['organizationName'] ?? 'Personal workspace' }} · {{ $context['roleName'] ?? 'Account access' }}</p><button type="submit">Continue</button></form>
@empty<p>You do not have access to this application. Ask an administrator for an invitation.</p>@endforelse
<form method="post" action="{{ $identity->url('logout') }}">@csrf<button type="submit">Sign out</button></form>
</main></body></html>
