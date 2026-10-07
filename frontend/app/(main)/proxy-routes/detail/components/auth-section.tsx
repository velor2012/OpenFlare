'use client';

import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { zodResolver } from '@hookform/resolvers/zod';
import { Controller, useForm } from 'react-hook-form';
import { useTranslations } from 'next-intl';
import { toast } from 'sonner';
import { z } from 'zod';

import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';
import { AdminAuthSourceService } from '@/lib/services/admin';
import type { ProxyRouteItem } from '@/lib/services/openflare';
import { proxyRouteFormIds } from '../helpers';
import { useRouteSectionSave } from '../hooks/use-route-section-save';
import { SectionShell } from './section-shell';

type AuthValues = {
  auth_mode: 'none' | 'basic' | 'oidc';
  basic_auth_username: string;
  basic_auth_password: string;
  oidc_auth_source_id: string;
};

function valuesFromRoute(route: ProxyRouteItem): AuthValues {
  return {
    auth_mode: route.oidc_auth_source_id
      ? 'oidc'
      : route.basic_auth_enabled
        ? 'basic'
        : 'none',
    basic_auth_username: route.basic_auth_username || '',
    basic_auth_password: route.basic_auth_password || '',
    oidc_auth_source_id: route.oidc_auth_source_id
      ? String(route.oidc_auth_source_id)
      : '',
  };
}

interface AuthSectionProps {
  route: ProxyRouteItem;
  onRouteUpdate: (route: ProxyRouteItem) => void;
  onSavingChange?: (saving: boolean) => void;
}

export function AuthSection({
  route,
  onRouteUpdate,
  onSavingChange,
}: AuthSectionProps) {
  const t = useTranslations('proxyRoutes');
  const {
    data: sources = [],
    isPending,
    isError,
  } = useQuery({
    queryKey: ['proxy-route-auth-sources'],
    queryFn: () => AdminAuthSourceService.listAuthSources(),
  });
  const schema = z
    .object({
      auth_mode: z.enum(['none', 'basic', 'oidc']),
      basic_auth_username: z.string(),
      basic_auth_password: z.string(),
      oidc_auth_source_id: z.string(),
    })
    .superRefine((values, context) => {
      if (values.auth_mode === 'basic') {
        if (!values.basic_auth_username.trim())
          context.addIssue({
            code: 'custom',
            path: ['basic_auth_username'],
            message: t('validation.enterUsername'),
          });
        if (!values.basic_auth_password.trim())
          context.addIssue({
            code: 'custom',
            path: ['basic_auth_password'],
            message: t('validation.enterPassword'),
          });
      }
      if (values.auth_mode === 'oidc') {
        if (!route.enable_https || !route.redirect_http)
          context.addIssue({
            code: 'custom',
            path: ['auth_mode'],
            message: t('oidcHTTPSRequired'),
          });
        if (
          !sources.some(
            (source) =>
              String(source.id) === values.oidc_auth_source_id &&
              source.is_active &&
              source.type === 'oidc',
          )
        )
          context.addIssue({
            code: 'custom',
            path: ['oidc_auth_source_id'],
            message: t('oidcSourceRequired'),
          });
      }
    });
  const form = useForm<AuthValues>({
    resolver: zodResolver(schema),
    defaultValues: valuesFromRoute(route),
  });
  const { saving, save } = useRouteSectionSave(
    route,
    onRouteUpdate,
    onSavingChange,
  );
  useEffect(() => {
    form.reset(valuesFromRoute(route));
  }, [form, route]);
  const mode = form.watch('auth_mode');

  return (
    <SectionShell
      title={t('auth')}
      description={t('authDesc')}
      formId={proxyRouteFormIds.auth}
      saving={saving}
    >
      <form
        id={proxyRouteFormIds.auth}
        onSubmit={form.handleSubmit(
          async (values) => {
            await save(
              {
                basic_auth_enabled: values.auth_mode === 'basic',
                basic_auth_username:
                  values.auth_mode === 'basic'
                    ? values.basic_auth_username.trim()
                    : '',
                basic_auth_password:
                  values.auth_mode === 'basic'
                    ? values.basic_auth_password.trim()
                    : '',
                oidc_auth_source_id:
                  values.auth_mode === 'oidc'
                    ? values.oidc_auth_source_id
                    : null,
              },
              t('authSaved'),
            );
          },
          () => toast.error(t('authFormInvalid')),
        )}
      >
        <FieldGroup>
          <Controller
            control={form.control}
            name='auth_mode'
            render={({ field, fieldState }) => (
              <Field data-invalid={fieldState.invalid}>
                <FieldLabel id='route-auth-mode-label'>
                  {t('authMode')}
                </FieldLabel>
                <ToggleGroup
                  type='single'
                  variant='outline'
                  value={field.value}
                  aria-labelledby='route-auth-mode-label'
                  onValueChange={(value) => {
                    if (value) field.onChange(value);
                  }}
                >
                  <ToggleGroupItem value='none'>
                    {t('authNone')}
                  </ToggleGroupItem>
                  <ToggleGroupItem value='basic'>
                    {t('authBasic')}
                  </ToggleGroupItem>
                  <ToggleGroupItem value='oidc'>
                    {t('authOIDC')}
                  </ToggleGroupItem>
                </ToggleGroup>
                <FieldDescription>{t('powHint')}</FieldDescription>
                <FieldError errors={[fieldState.error]} />
              </Field>
            )}
          />
          {mode === 'oidc' ? (
            <Controller
              control={form.control}
              name='oidc_auth_source_id'
              render={({ field, fieldState }) => (
                <Field data-invalid={fieldState.invalid}>
                  <FieldLabel htmlFor='route-oidc-source'>
                    {t('oidcSource')}
                  </FieldLabel>
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                    disabled={isPending || isError}
                  >
                    <SelectTrigger
                      id='route-oidc-source'
                      aria-invalid={fieldState.invalid}
                    >
                      <SelectValue placeholder={t('oidcSourceRequired')} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {sources
                          .filter((source) => source.type === 'oidc')
                          .map((source) => (
                            <SelectItem
                              key={source.id}
                              value={String(source.id)}
                              disabled={!source.is_active}
                            >
                              {source.display_name || source.name}
                              {!source.is_active
                                ? ` (${t('oidcDisabled')})`
                                : ''}
                            </SelectItem>
                          ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <FieldDescription>
                    {isError
                      ? t('oidcLoadFailed')
                      : isPending
                        ? t('oidcLoading')
                        : sources.every((source) => !source.is_active)
                          ? t('oidcNoSources')
                          : t('oidcHint')}
                  </FieldDescription>
                  <FieldError errors={[fieldState.error]} />
                </Field>
              )}
            />
          ) : null}
          {mode === 'basic' ? (
            <>
              <Field data-invalid={!!form.formState.errors.basic_auth_username}>
                <FieldLabel htmlFor='route-basic-username'>
                  {t('username')}
                </FieldLabel>
                <Input
                  id='route-basic-username'
                  aria-invalid={!!form.formState.errors.basic_auth_username}
                  {...form.register('basic_auth_username')}
                />
                <FieldError
                  errors={[form.formState.errors.basic_auth_username]}
                />
              </Field>
              <Field data-invalid={!!form.formState.errors.basic_auth_password}>
                <FieldLabel htmlFor='route-basic-password'>
                  {t('password')}
                </FieldLabel>
                <Input
                  id='route-basic-password'
                  type='text'
                  aria-invalid={!!form.formState.errors.basic_auth_password}
                  {...form.register('basic_auth_password')}
                />
                <FieldError
                  errors={[form.formState.errors.basic_auth_password]}
                />
              </Field>
            </>
          ) : null}
        </FieldGroup>
      </form>
    </SectionShell>
  );
}
