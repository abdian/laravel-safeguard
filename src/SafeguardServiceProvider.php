<?php

namespace Abdian\LaravelSafeguard;

use Abdian\LaravelSafeguard\Rules\SafeguardMime;
use Abdian\LaravelSafeguard\Rules\SafeguardPhp;
use Abdian\LaravelSafeguard\Rules\SafeguardSvg;
use Abdian\LaravelSafeguard\Rules\SafeguardImage;
use Abdian\LaravelSafeguard\Rules\SafeguardPdf;
use Abdian\LaravelSafeguard\Rules\SafeguardDimensions;
use Abdian\LaravelSafeguard\Rules\SafeguardPages;
use Abdian\LaravelSafeguard\Rules\Safeguard;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\ServiceProvider;

/**
 * SafeguardServiceProvider - Main service provider for Laravel Safeguard package
 *
 * This provider registers all validation rules and publishes configuration files
 */
class SafeguardServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge package config with application config
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
        // Publish configuration file
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/config/safeguard.php' => config_path('safeguard.php'),
            ], 'safeguard-config');
        }

        // Register custom validation rules
        $this->registerValidationRules();
    }

    /**
     * Register custom validation rules with Laravel's validator
     *
     * @return void
     */
    protected function registerValidationRules(): void
    {
        // Register safeguard_mime validation rule
        Validator::extend('safeguard_mime', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardMime($parameters);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_mime', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_mime', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_php validation rule
        Validator::extend('safeguard_php', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardPhp();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_php', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_php', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_svg validation rule
        Validator::extend('safeguard_svg', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardSvg();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_svg', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_svg', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_image validation rule
        Validator::extend('safeguard_image', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardImage();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_image', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_image', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_pdf validation rule
        Validator::extend('safeguard_pdf', function ($attribute, $value, $parameters, $validator) {
            $rule = new SafeguardPdf();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_pdf', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_pdf', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_dimensions validation rule
        Validator::extend('safeguard_dimensions', function ($attribute, $value, $parameters, $validator) {
            // Parse parameters: max_width, max_height, min_width (optional), min_height (optional)
            $maxWidth = isset($parameters[0]) ? (int) $parameters[0] : null;
            $maxHeight = isset($parameters[1]) ? (int) $parameters[1] : null;
            $minWidth = isset($parameters[2]) ? (int) $parameters[2] : null;
            $minHeight = isset($parameters[3]) ? (int) $parameters[3] : null;

            $rule = new SafeguardDimensions($maxWidth, $maxHeight, $minWidth, $minHeight);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_dimensions', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_dimensions', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard_pages validation rule
        Validator::extend('safeguard_pages', function ($attribute, $value, $parameters, $validator) {
            // Parse parameters: min_pages (optional), max_pages (optional)
            $minPages = isset($parameters[0]) ? (int) $parameters[0] : null;
            $maxPages = isset($parameters[1]) ? (int) $parameters[1] : null;

            $rule = new SafeguardPages($minPages, $maxPages);
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard_pages', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard_pages', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });

        // Register safeguard validation rule (comprehensive security check)
        Validator::extend('safeguard', function ($attribute, $value, $parameters, $validator) {
            $rule = new Safeguard();
            $fails = false;
            $errorMessage = '';

            $rule->validate($attribute, $value, function ($message) use (&$fails, &$errorMessage) {
                $fails = true;
                $errorMessage = $message;
            });

            if ($fails) {
                $validator->addReplacer('safeguard', function ($message, $attribute, $rule, $parameters) use ($errorMessage) {
                    return $errorMessage;
                });
                return false;
            }

            return true;
        });

        // Add custom error message
        Validator::replacer('safeguard', function ($message, $attribute, $rule, $parameters) {
            return $message;
        });
    }
}
