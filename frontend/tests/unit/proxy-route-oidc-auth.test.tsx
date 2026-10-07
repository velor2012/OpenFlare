import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { NextIntlClientProvider } from 'next-intl';
import { beforeEach, expect, it, vi } from 'vitest';

import { AuthSection } from '@/app/(main)/proxy-routes/detail/components/auth-section';
import { buildPayloadFromRoute } from '@/app/(main)/proxy-routes/components/helpers';
import type { ProxyRouteItem } from '@/lib/services/openflare';
import zhCN from '@/messages/zh-CN.json';

const { save, listSources } = vi.hoisted(() => ({
  save: vi.fn(),
  listSources: vi.fn(),
}));
vi.mock(
  '@/app/(main)/proxy-routes/detail/hooks/use-route-section-save',
  () => ({ useRouteSectionSave: () => ({ saving: false, save }) }),
);
vi.mock('@/lib/services/admin', () => ({
  AdminAuthSourceService: { listAuthSources: listSources },
}));

const route = {
  id: 1,
  enable_https: true,
  redirect_http: true,
  oidc_auth_source_id: '7',
  origin_url: 'http://origin.test',
} as ProxyRouteItem;

function renderAuth(item = route) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <NextIntlClientProvider
      locale='zh-CN'
      messages={zhCN}
      timeZone='Asia/Shanghai'
    >
      <QueryClientProvider client={client}>
        <AuthSection route={item} onRouteUpdate={() => {}} />
      </QueryClientProvider>
    </NextIntlClientProvider>,
  );
}

beforeEach(() => {
  save.mockReset();
  listSources.mockResolvedValue([
    { id: 7, type: 'oidc', display_name: 'Casdoor', is_active: true },
  ]);
});

it('loads the existing OIDC source and saves its ID without Basic credentials', async () => {
  const { container } = renderAuth();
  await waitFor(() =>
    expect(screen.getByRole('combobox')).toHaveTextContent('Casdoor'),
  );
  fireEvent.submit(container.querySelector('form')!);
  await waitFor(() =>
    expect(save).toHaveBeenCalledWith(
      {
        basic_auth_enabled: false,
        basic_auth_username: '',
        basic_auth_password: '',
        oidc_auth_source_id: '7',
      },
      '认证配置已保存',
    ),
  );
  expect(
    buildPayloadFromRoute(route, { origin_host: 'origin.test' })
      .oidc_auth_source_id,
  ).toBe('7');
});

it('rejects OIDC when HTTPS redirection is disabled', async () => {
  const { container } = renderAuth({ ...route, redirect_http: false });
  await waitFor(() =>
    expect(screen.getByRole('combobox')).toHaveTextContent('Casdoor'),
  );
  fireEvent.submit(container.querySelector('form')!);
  expect(
    await screen.findByText('请先在域名配置中开启 HTTPS 和 HTTP 跳转 HTTPS'),
  ).toBeInTheDocument();
  expect(save).not.toHaveBeenCalled();
});

it('clears the source when switching to no authentication', async () => {
  const { container } = renderAuth();
  await waitFor(() =>
    expect(screen.getByRole('combobox')).toHaveTextContent('Casdoor'),
  );
  fireEvent.click(screen.getByRole('radio', { name: '无认证' }));
  fireEvent.submit(container.querySelector('form')!);
  await waitFor(() =>
    expect(save).toHaveBeenCalledWith(
      expect.objectContaining({ oidc_auth_source_id: null }),
      '认证配置已保存',
    ),
  );
});
