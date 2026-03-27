---
title: "Frontend & UI/UX Terminology: The Visual Language of the Web"
date: 2026-01-27 09:00:00 +0900
categories: [Engineering, UI/UX & Frontend Foundations]
image: "/assets/thumbnails/2026-01-27-frontend-ui-terminology.png"
bilingual: true
---

## Frontend & UI/UX Terminology: The Visual Language of the Web

If you've ever looked at a modern website and heard someone say *"the hero needs more breathing room"* or *"let's add a sticky nav with a segment control"* and nodded along while having no idea what they meant—this post is for you.

Frontend developers and designers share a common vocabulary that makes collaboration faster. Once you know these terms, you start *seeing* websites differently: every page is a collection of named components with predictable patterns.

## Part 1: Page Structure & Layout

### Hero / Hero Section / Hero Container

The **hero** is the large, prominent section at the very top of a page—the first thing you see before scrolling. The term comes from print design ("hero image" = the dominant visual).

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│            BIG HEADLINE TEXT HERE                       │  ← Hero Section
│            Supporting subtitle                          │
│            [CTA Button]                                 │
│                                                         │
│  [Full-width background image or video]                 │
│                                                         │
└─────────────────────────────────────────────────────────┘
│  About section...                                       │
│  Features section...                                    │
└─────────────────────────────────────────────────────────┘
```

A hero section typically contains:
- A **headline** (H1)
- A **subheadline** or description
- One or two **CTA buttons** (Call to Action)
- A **background image, video, or gradient**

You'll often hear: *"The hero feels too busy"*, *"Increase the hero height"*, *"Let's A/B test two hero headlines."*

### Above the Fold / Below the Fold

Originally a newspaper term: content visible without unfolding the paper = "above the fold."

On the web:
- **Above the fold**: content visible without scrolling (the hero usually lives here)
- **Below the fold**: content that requires scrolling to reach

The fold is not a fixed pixel value—it changes depending on the user's screen size and browser chrome. This is why designers talk about *"viewport height"* (`100vh`).

### Viewport

The **viewport** is the visible area of a web page in the user's browser window. It's not the full page—just the portion currently visible.

CSS uses `vw` (viewport width) and `vh` (viewport height) as units:
- `100vw` = the full width of the browser window
- `100vh` = the full height of the browser window

```css
.hero {
  height: 100vh; /* Full screen height */
  width: 100%;
}
```

### Container / Wrapper

A **container** (sometimes called a **wrapper**) is an invisible box that constrains the maximum width of content and centers it on the page.

Without a container, text would stretch wall-to-wall on a wide monitor, becoming hard to read. Containers create consistent margins.

```
Browser window (1440px wide)
┌────────────────────────────────────────────────────────┐
│   [spacer]   [Container: max-width 1200px]   [spacer]  │
│              ┌───────────────────────────┐             │
│              │ Your content lives here   │             │
│              └───────────────────────────┘             │
└────────────────────────────────────────────────────────┘
```

```css
.container {
  max-width: 1200px;
  margin: 0 auto; /* Center horizontally */
  padding: 0 24px; /* Side gutters */
}
```

### Section

A **section** is a thematic block of content on a page. Most marketing pages are built by stacking sections vertically:

```
[Hero Section]
[Features Section]
[Testimonials Section]
[Pricing Section]
[Footer Section]
```

Sections usually have their own background color or image, padding, and a heading. In HTML, `<section>` is the semantic tag for this pattern.

### Card

A **card** is a self-contained UI component that groups related content—typically an image, a title, a description, and an action link. Cards are everywhere: product listings, blog post previews, user profiles.

```
┌──────────────────────┐
│  [Image or thumbnail]│
│                      │
│  Post Title          │
│  Short description   │
│  Feb 27, 2025        │
│                      │
│  [Read More →]       │
└──────────────────────┘
```

A **card grid** arranges multiple cards in a responsive grid. When cards wrap to fewer columns on mobile, that responsive behavior is handled with CSS Grid or Flexbox.

### Grid vs. Flexbox

Two CSS layout systems you'll hear constantly:

| | CSS Grid | Flexbox |
|---|---|---|
| **Dimension** | Two-dimensional (rows AND columns) | One-dimensional (row OR column) |
| **Best for** | Page-level layouts, card grids | Navbars, centering items, component internals |
| **Mental model** | Spreadsheet | Line of items |

Example: A 3-column card grid → CSS Grid. A navbar with logo on the left and links on the right → Flexbox.

## Part 2: Navigation Components

### Navigation Bar (Navbar)

The **navbar** (navigation bar) is the horizontal bar at the top of a page containing the site logo and links. It's the primary wayfinding element.

```
┌──────────────────────────────────────────────────────────┐
│  Logo    Home    About    Blog    Projects    [Contact]   │
└──────────────────────────────────────────────────────────┘
```

Components of a typical navbar:
- **Logo / Wordmark**: links to the homepage
- **Navigation links**: primary pages
- **CTA button**: the most important action (sign up, contact, etc.)
- **Hamburger menu** (on mobile): replaces the links with a collapsible menu

### Sticky Nav / Fixed Nav / Floating Nav

These terms describe how the navbar behaves on scroll:

| Term | Behavior |
|---|---|
| **Static** | Scrolls away with the page. Disappears when you scroll down. |
| **Sticky** | Stays at the top once you scroll past it (`position: sticky`) |
| **Fixed** | Always at the top, never moves (`position: fixed`) |
| **Floating Nav** | Fixed/sticky navbar that "floats" above the page—usually with a background blur or shadow, slightly inset from the edges |

A **floating nav** looks like this:

```
     ┌───────────────────────────────────────────┐
     │ Logo        Home  About  Blog   [Contact] │  ← floating, not full-width
     └───────────────────────────────────────────┘
     (has rounded corners, shadow, backdrop blur)
```

```css
.floating-nav {
  position: fixed;
  top: 16px;
  left: 50%;
  transform: translateX(-50%);
  width: calc(100% - 48px);
  max-width: 900px;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.8);
  backdrop-filter: blur(12px);
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.08);
}
```

### Breadcrumb

A **breadcrumb** is a secondary navigation trail showing the user's current location in the site hierarchy.

```
Home  >  Blog  >  Engineering  >  This Post
```

Breadcrumbs are especially useful on deep content sites and also help SEO by making site structure clear to crawlers.

### Hamburger Menu

The **hamburger menu** (☰) is the three-line icon that, when clicked, reveals a hidden navigation menu. Standard on mobile where screen width can't accommodate a full navbar. Often reveals a **drawer**—a panel that slides in from the side or top.

### Segment Control / Tab Bar

A **segment control** (also called a **tab bar** in mobile contexts) is a set of mutually exclusive options presented as adjacent buttons—selecting one deselects the others. It controls which content is currently visible.

```
┌──────────┬──────────┬──────────┐
│  Daily   │  Weekly  │  Monthly │   ← Segment Control
└──────────┴──────────┴──────────┘
│                                 │
│   [Content changes based on     │
│    selected segment]            │
│                                 │
└─────────────────────────────────┘
```

On mobile, segment controls are everywhere (iOS Settings, analytics dashboards). On desktop, the same pattern is often called **tabs**.

### Pagination

**Pagination** splits content across multiple pages with numbered navigation links.

```
← Prev   1   2   [3]   4   5   Next →
```

Alternatives are **infinite scroll** (content loads automatically) or **load more** (a button that appends more content). Pagination is better for findability; infinite scroll is better for consumption.

## Part 3: Interactive Components

### CTA (Call to Action)

A **CTA** is any element designed to prompt a specific user action—usually a button.

```
[Sign Up Free]   ← Primary CTA (high visual weight)
[Learn More]     ← Secondary CTA (lower visual weight)
```

Good CTAs are action-oriented ("Download," "Get Started"), specific, and visually prominent.

### Modal / Dialog

A **modal** (also called a **dialog**) is an overlay that appears on top of the current page, temporarily blocking interaction with the page behind it.

```
┌────────────────────────────────────────────┐
│                                            │ ← background page (dimmed)
│   ┌──────────────────────────┐             │
│   │   Modal Title         ✕  │             │ ← modal
│   │                          │
│   │   Are you sure?          │
│   │                          │
│   │  [Cancel]   [Confirm]    │
│   └──────────────────────────┘
└────────────────────────────────────────────┘
```

Best reserved for: confirmation dialogs for destructive actions, quick-add forms, and authentication flows.

### Toast Notification

A **toast** is a brief, non-blocking notification that appears temporarily at the edge of the screen and disappears automatically.

```
                              ┌─────────────────────┐
                              │ ✓ Changes saved      │  ← toast
                              └─────────────────────┘
```

Called a "toast" because it pops up like toast from a toaster. Used for success confirmations, error alerts, and status updates.

### Tooltip

A **tooltip** is a small informational label that appears when you hover over an element. Used to explain UI elements that aren't clear from their label alone—especially icon buttons.

### Accordion

An **accordion** is a vertically stacked list of items where each item can be expanded or collapsed to show/hide content.

```
▶ What is your refund policy?
▼ How do I reset my password?
  Click "Forgot password" on the login page,
  then enter your email address.
▶ Do you support SSO?
```

Common in FAQs, settings panels, and mobile menus.

### Carousel / Slider

A **carousel** (also called a **slider**) is a component that displays a series of items one at a time, with controls to cycle through them.

```
← [ Card 1 / Card 2 / Card 3 ] →
        ●  ○  ○  ← indicator dots
```

Use sparingly—research shows users rarely interact with slides beyond the first.

### Toggle / Switch

A **toggle** (or **switch**) is a binary on/off control, visually distinct from a checkbox. Common in settings panels.

```
Dark Mode      ●────────  OFF
Notifications  ────────●  ON
```

## Part 4: Typography Hierarchy

Typography on the web follows a **heading hierarchy** using HTML tags H1 through H6.

| Tag | Role | Typical Usage |
|---|---|---|
| `<h1>` | Page title | One per page; the main topic |
| `<h2>` | Section heading | Main sections of the page |
| `<h3>` | Subsection heading | Sub-topics within a section |
| `<h4>`–`<h6>` | Deeper levels | Rarely needed; avoid deep nesting |
| `<p>` | Body copy | Regular paragraph text |
| `<caption>` | Caption | Image or table descriptions |
| `<label>` | Form label | Labels for form inputs |

A common mistake: using heading tags for visual size rather than semantic meaning. Use CSS for size; use heading tags for structure.

## Quick Reference Cheat Sheet

| Term | What it is |
|---|---|
| **Hero** | The big first section of a page |
| **Above the fold** | Visible without scrolling |
| **Viewport** | Visible area in the browser |
| **Container** | Width-constraining wrapper for content |
| **Card** | Self-contained content unit |
| **Navbar** | Horizontal navigation bar at the top |
| **Floating Nav** | Fixed navbar with blur/shadow effect |
| **Sticky Nav** | Navbar that attaches to top on scroll |
| **Hamburger Menu** | ☰ icon that reveals mobile navigation |
| **Segment Control** | Mutually exclusive button group for filtering/tabs |
| **Breadcrumb** | `Home > Category > Page` trail |
| **CTA** | Button or link prompting a specific action |
| **Modal** | Overlay dialog requiring interaction |
| **Toast** | Auto-dismissing corner notification |
| **Tooltip** | Hover label for UI element explanation |
| **Accordion** | Expand/collapse content list |
| **Carousel** | Sliding content component |
| **Toggle** | Binary on/off switch |

---

## 프론트엔드 & UI/UX 용어: 웹의 시각적 언어

*"히어로에 여백이 더 필요해요"* 혹은 *"세그먼트 컨트롤이 있는 플로팅 네비를 추가하죠"* 같은 말을 들었을 때 고개를 끄덕였지만 실제로는 무슨 뜻인지 몰랐던 적이 있다면—이 포스팅이 바로 그 분들을 위한 것입니다.

프론트엔드 개발자와 디자이너는 협업을 빠르게 하기 위한 공통 어휘를 공유합니다. 이 용어들을 알게 되면 웹사이트를 다르게 *보기* 시작합니다. 모든 페이지는 예측 가능한 패턴을 가진 이름 붙은 컴포넌트들의 집합입니다.

## 1부: 페이지 구조 & 레이아웃

### 히어로 / 히어로 섹션 / 히어로 컨테이너 (Hero)

**히어로**는 페이지 최상단의 크고 눈에 띄는 섹션으로, 스크롤하기 전 처음 보이는 부분입니다. "히어로 이미지"라는 인쇄 디자인 용어에서 유래했습니다.

히어로 섹션에는 보통 다음이 포함됩니다:
- **헤드라인** (H1)
- **서브헤드라인** 또는 설명문
- 하나 또는 두 개의 **CTA 버튼** (행동 유도)
- **배경 이미지, 영상 또는 그라디언트**

*"히어로가 너무 복잡해요"*, *"히어로 높이를 키워요"*와 같은 표현을 자주 듣게 됩니다.

### 스크롤 위/아래 (Above the Fold / Below the Fold)

원래 신문 용어입니다. 신문을 펼치지 않고 볼 수 있는 내용이 "fold 위"입니다.

웹에서는:
- **Above the fold**: 스크롤 없이 보이는 콘텐츠 (히어로가 보통 여기 있습니다)
- **Below the fold**: 스크롤해야 보이는 콘텐츠

Fold는 고정된 픽셀 값이 아닙니다. 사용자의 화면 크기와 브라우저에 따라 달라집니다. 그래서 디자이너들이 *"뷰포트 높이"*(`100vh`)를 이야기하는 것입니다.

### 뷰포트 (Viewport)

**뷰포트**는 사용자의 브라우저 창에서 보이는 웹 페이지 영역입니다. 전체 페이지가 아닌, 현재 보이는 부분만을 의미합니다.

CSS는 `vw`(뷰포트 너비)와 `vh`(뷰포트 높이)를 단위로 사용합니다:
- `100vw` = 브라우저 창의 전체 너비
- `100vh` = 브라우저 창의 전체 높이

### 컨테이너 / 래퍼 (Container / Wrapper)

**컨테이너**(래퍼라고도 함)는 콘텐츠의 최대 너비를 제한하고 페이지 중앙에 배치하는 보이지 않는 박스입니다.

컨테이너가 없으면 넓은 모니터에서 텍스트가 화면 끝까지 늘어나 읽기 어려워집니다.

```css
.container {
  max-width: 1200px;
  margin: 0 auto; /* 수평 중앙 정렬 */
  padding: 0 24px; /* 좌우 여백 */
}
```

### 섹션 (Section)

**섹션**은 페이지에서 주제별로 구분된 콘텐츠 블록입니다. 대부분의 마케팅 페이지는 섹션을 세로로 쌓아 구성합니다:

```
[히어로 섹션] → [기능 섹션] → [후기 섹션] → [가격 섹션] → [푸터]
```

### 카드 (Card)

**카드**는 관련 콘텐츠를 하나로 묶는 독립적인 UI 컴포넌트입니다. 보통 이미지, 제목, 설명, 액션 링크를 포함합니다. 쇼핑몰 상품 목록, 블로그 포스트 미리보기, 사용자 프로필 등 어디서나 볼 수 있습니다.

**카드 그리드**는 여러 카드를 반응형 그리드에 배치하는 레이아웃입니다.

### Grid vs. Flexbox

끊임없이 들을 두 CSS 레이아웃 시스템:

| | CSS Grid | Flexbox |
|---|---|---|
| **방향** | 2차원 (행과 열 동시) | 1차원 (행 또는 열) |
| **최적 용도** | 페이지 레이아웃, 카드 그리드 | 네비게이션 바, 아이템 중앙 정렬 |
| **사고 모델** | 스프레드시트 | 아이템 한 줄 |

예시: 3열 카드 그리드 → CSS Grid. 왼쪽 로고, 오른쪽 링크가 있는 네비게이션 바 → Flexbox.

## 2부: 네비게이션 컴포넌트

### 네비게이션 바 (Navbar)

**네비게이션 바**(Navbar)는 페이지 상단의 가로 바로 사이트 로고와 링크를 포함합니다. 사이트의 주요 길 안내 역할을 합니다.

전형적인 구성요소:
- **로고/워드마크**: 홈페이지로 연결
- **네비게이션 링크**: 주요 페이지들
- **CTA 버튼**: 가장 중요한 액션 (회원가입, 문의 등)
- **햄버거 메뉴** (모바일): 접을 수 있는 메뉴로 링크를 대체

### 플로팅 네비 / 스티키 네비 / 고정 네비

스크롤 시 네비게이션 바의 동작 방식을 설명하는 용어들:

| 용어 | 동작 방식 |
|---|---|
| **Static(정적)** | 페이지와 함께 스크롤됨. 아래로 스크롤하면 사라짐 |
| **Sticky(스티키)** | 스크롤하다 상단에 닿으면 고정됨 (`position: sticky`) |
| **Fixed(고정)** | 항상 상단에 고정. 절대 움직이지 않음 (`position: fixed`) |
| **Floating Nav(플로팅 네비)** | 배경 블러나 그림자를 가진 fixed/sticky 네비. 가장자리에서 약간 안쪽에 위치 |

**플로팅 네비**는 모서리가 둥글고 그림자, 배경 블러 효과가 있습니다. SaaS 제품 사이트와 디자인 포트폴리오에서 "모던"하고 "프리미엄"한 느낌을 주기 위해 많이 사용됩니다.

### 브레드크럼 (Breadcrumb)

**브레드크럼**은 사이트 계층에서 사용자의 현재 위치를 보여주는 보조 네비게이션 경로입니다.

```
홈 > 블로그 > 엔지니어링 > 이 포스팅
```

깊은 콘텐츠 사이트에서 특히 유용하고 SEO에도 도움이 됩니다.

### 햄버거 메뉴 (Hamburger Menu)

**햄버거 메뉴**(☰)는 클릭하면 숨겨진 네비게이션 메뉴가 나타나는 세 줄 아이콘입니다. 세 개의 수평선이 단면에서 보면 햄버거처럼 생겨서 붙은 이름입니다.

모바일에서 전체 네비게이션 바를 수용하기 어려운 문제를 해결합니다. 클릭하면 보통 **드로어(Drawer)**(옆이나 위에서 슬라이드 인하는 패널)가 나타납니다.

### 세그먼트 컨트롤 / 탭 바 (Segment Control / Tab Bar)

**세그먼트 컨트롤**은 서로 배타적인 옵션들을 인접한 버튼 형태로 표시하는 컴포넌트입니다. 하나를 선택하면 나머지 선택이 해제되며, 현재 보이는 콘텐츠를 제어합니다.

```
┌──────────┬──────────┬──────────┐
│  일간   │  주간  │  월간  │  ← 세그먼트 컨트롤
└──────────┴──────────┴──────────┘
│                                 │
│   선택된 세그먼트에 따라        │
│   콘텐츠가 바뀜                 │
│                                 │
└─────────────────────────────────┘
```

iOS 설정, 분석 대시보드 등 모바일에서 광범위하게 사용됩니다. 데스크톱에서는 동일한 패턴을 **탭(Tab)**이라고 부르는 경우가 많습니다.

### 페이지네이션 (Pagination)

**페이지네이션**은 콘텐츠를 번호가 매겨진 네비게이션 링크로 여러 페이지에 나누는 패턴입니다.

```
← 이전   1   2   [3]   4   5   다음 →
```

대안으로 **무한 스크롤**(자동으로 콘텐츠 로드) 또는 **더 불러오기** 버튼 패턴이 있습니다.

## 3부: 인터랙티브 컴포넌트

### CTA (행동 유도)

**CTA(Call to Action)**는 특정 사용자 행동을 유도하기 위해 설계된 모든 요소입니다.

좋은 CTA의 조건:
- **행동 지향적** ("다운로드", "시작하기", "무료로 써보기")
- **구체적** ("iOS 앱 다운로드"가 "여기 클릭"보다 좋음)
- **시각적으로 두드러짐** (높은 대비, 명확한 위치)

### 모달 / 다이얼로그 (Modal / Dialog)

**모달**은 현재 페이지 위에 나타나는 오버레이로, 뒤의 페이지와의 인터랙션을 일시적으로 차단합니다. 사용자는 모달과 상호작용(또는 닫기) 후에 페이지로 돌아갈 수 있습니다.

최적 사용 사례: 되돌릴 수 없는 행동의 확인 다이얼로그, 빠른 추가 폼, 인증 플로우.

### 토스트 알림 (Toast Notification)

**토스트**는 일시적으로 나타났다가 자동으로 사라지는 간단한 비차단 알림입니다. 토스터에서 토스트가 튀어오르는 것처럼 팝업되어서 "토스트"라고 불립니다.

성공 확인, 오류 경고, 상태 업데이트에 사용됩니다.

### 툴팁 (Tooltip)

**툴팁**은 요소에 마우스를 올리거나 탭할 때 나타나는 작은 설명 레이블입니다. 레이블만으로는 불명확한 UI 요소—특히 아이콘 버튼—을 설명하는 데 사용됩니다.

### 아코디언 (Accordion)

**아코디언**은 수직으로 쌓인 항목 목록으로, 각 항목을 펼치거나 접어 콘텐츠를 보이게/숨기게 할 수 있습니다. FAQ, 설정 패널, 모바일 메뉴에서 흔히 볼 수 있습니다.

### 캐러셀 / 슬라이더 (Carousel / Slider)

**캐러셀**은 한 번에 하나의 항목을 표시하고 화살표, 점, 스와이프로 순환할 수 있는 컴포넌트입니다. 절제해서 사용하고, 항상 첫 번째 슬라이드에 가장 중요한 콘텐츠를 배치하세요.

### 토글 / 스위치 (Toggle / Switch)

**토글**(스위치)은 이진법적인 켜기/끄기 컨트롤로, 체크박스와 시각적으로 구분됩니다. 설정 패널에서 흔히 사용됩니다.

## 4부: 타이포그래피 계층 구조

웹 타이포그래피는 HTML 태그 H1부터 H6까지 **헤딩 계층 구조**를 따릅니다.

| 태그 | 역할 | 일반적 사용 |
|---|---|---|
| `<h1>` | 페이지 제목 | 페이지당 하나; 주요 주제 |
| `<h2>` | 섹션 헤딩 | 페이지의 주요 섹션 |
| `<h3>` | 서브섹션 헤딩 | 섹션 내 하위 주제 |
| `<h4>`–`<h6>` | 더 깊은 단계 | 거의 불필요; 깊은 중첩 피하기 |
| `<p>` | 본문 | 일반 단락 텍스트 |
| `<caption>` | 캡션 | 이미지 또는 표 설명 |
| `<label>` | 폼 레이블 | 폼 입력 레이블 |

흔한 실수: 시각적 크기를 위해 헤딩 태그를 사용하는 것. 크기는 CSS로, 구조는 헤딩 태그로 처리하세요.

## 빠른 참조 치트 시트

| 용어 | 한 줄 설명 |
|---|---|
| **히어로 (Hero)** | 페이지 첫 번째 대형 섹션 |
| **Above the fold** | 스크롤 없이 보이는 영역 |
| **뷰포트 (Viewport)** | 브라우저에서 보이는 영역 |
| **컨테이너 (Container)** | 콘텐츠 너비를 제한하는 래퍼 |
| **카드 (Card)** | 독립적인 콘텐츠 단위 |
| **네비게이션 바 (Navbar)** | 상단 가로 네비게이션 바 |
| **플로팅 네비 (Floating Nav)** | 블러/그림자 효과가 있는 고정 네비 |
| **스티키 네비 (Sticky Nav)** | 스크롤 시 상단에 고정되는 네비 |
| **햄버거 메뉴** | ☰ 모바일 네비게이션을 열어주는 아이콘 |
| **세그먼트 컨트롤** | 필터링/탭을 위한 상호 배타적 버튼 그룹 |
| **브레드크럼 (Breadcrumb)** | `홈 > 카테고리 > 페이지` 경로 표시 |
| **CTA** | 특정 행동을 유도하는 버튼/링크 |
| **모달 (Modal)** | 상호작용이 필요한 오버레이 다이얼로그 |
| **토스트 (Toast)** | 자동으로 사라지는 모서리 알림 |
| **툴팁 (Tooltip)** | 마우스 오버 시 나타나는 설명 레이블 |
| **아코디언 (Accordion)** | 펼치기/접기 콘텐츠 목록 |
| **캐러셀 (Carousel)** | 슬라이드 콘텐츠 컴포넌트 |
| **토글 (Toggle)** | 이진 켜기/끄기 스위치 |
