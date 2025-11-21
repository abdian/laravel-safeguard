<?php

namespace Abdian\LaravelSafeguard;

use Illuminate\Support\ServiceProvider;

class SafeguardServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/config/safeguard.php',
            'safeguard'
        );
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/config/safeguard.php' => config_path('safeguard.php'),
            ], 'safeguard-config');
        }
    }
}
