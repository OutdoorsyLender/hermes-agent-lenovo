import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { I18nProvider } from '@/i18n'
import { refreshBackgroundProcesses } from '@/store/composer-status'
import { refreshSessionControl } from '@/store/session-control'
import { clearAllSessionStates, dropSessionState, recordSessionEventScope } from '@/store/session-states'
import { resetThreadScroll, setThreadAtBottom } from '@/store/thread-scroll'

import { ComposerStatusStack } from './index'

vi.mock('@/store/composer-status', async importOriginal => {
  const actual = await importOriginal<typeof ComposerStatusStore>()

  return {
    ...actual,
    refreshBackgroundProcesses: vi.fn(async () => undefined)
  }
})

vi.mock('@/store/session-control', async importOriginal => {
  const actual = await importOriginal<typeof SessionControlStore>()

  return {
    ...actual,
    refreshSessionControl: vi.fn(async () => undefined)
  }
})

vi.mock('./use-subagent-snapshot', () => ({
  useSubagentSnapshot: vi.fn()
}))

import type * as ComposerStatusStore from '@/store/composer-status'
import type * as SessionControlStore from '@/store/session-control'

class TestResizeObserver {
  disconnect() {}
  observe() {}
  unobserve() {}
}

vi.stubGlobal('ResizeObserver', TestResizeObserver)

function renderStack(sessionId: string) {
  return render(
    <MemoryRouter>
      <I18nProvider configClient={null} initialLocale="en">
        <ComposerStatusStack queue={null} sessionId={sessionId} />
      </I18nProvider>
    </MemoryRouter>
  )
}

afterEach(() => {
  cleanup()
  clearAllSessionStates()
  vi.clearAllMocks()
})

describe('ComposerStatusStack scroll treatment', () => {
  beforeEach(() => {
    setThreadAtBottom(false, 'sess-a')
  })

  afterEach(() => {
    resetThreadScroll('sess-a')
  })

  it('dims only the status content while keeping the dock card opaque', () => {
    const view = render(
      <MemoryRouter>
        <I18nProvider configClient={null} initialLocale="en">
          <ComposerStatusStack queue={<div>Queued task</div>} sessionId="sess-a" />
          <ComposerStatusStack queue={<div>Sibling task</div>} sessionId="sess-b" />
        </I18nProvider>
      </MemoryRouter>
    )

    const card = view.container.querySelector<HTMLElement>('[class*="bg-(--composer-fill)"]')
    const dimmedContent = screen.getByText('Queued task').closest<HTMLElement>('.opacity-30')

    expect(card).not.toBeNull()
    expect(card?.classList.contains('opacity-30')).toBe(false)
    expect(dimmedContent).not.toBeNull()
    expect(dimmedContent).not.toBe(card)
    expect(card?.contains(dimmedContent)).toBe(true)
    expect(screen.getByText('Sibling task').closest('.opacity-30')).toBeNull()
  })
})

describe('ComposerStatusStack session owner discovery', () => {
  it('hydrates exactly once after an inbound event proves the session owner', async () => {
    renderStack('rt-late-owner')

    await waitFor(() => {
      expect(refreshSessionControl).toHaveBeenCalledTimes(1)
      expect(refreshBackgroundProcesses).toHaveBeenCalledTimes(1)
    })

    act(() => {
      recordSessionEventScope({ connectionId: 'local', profile: 'coder', session_id: 'rt-late-owner' })
    })

    await waitFor(() => {
      expect(refreshSessionControl).toHaveBeenCalledTimes(2)
      expect(refreshBackgroundProcesses).toHaveBeenCalledTimes(2)
    })

    act(() => {
      recordSessionEventScope({ connectionId: 'local', profile: 'coder', session_id: 'rt-late-owner' })
      dropSessionState('rt-late-owner')
    })

    expect(refreshSessionControl).toHaveBeenCalledTimes(2)
    expect(refreshBackgroundProcesses).toHaveBeenCalledTimes(2)
  })
})
