DARK THEME DESIGN SYSTEM
STYLE: LOKI / TVA INSPIRED
MOOD: Dark, cinematic, mysterious, premium, industrial, futuristic, sophisticated
IMPORTANT: Take inspiration from the visual language of Loki/TVA. Do NOT directly copy Marvel logos, characters, artwork, or copyrighted UI elements.

==================================================
1. CORE COLOR SYSTEM
==================================================

BACKGROUND
Primary Background:        #080A09
Secondary Background:      #0B0F0D
Tertiary Background:       #101412

SURFACES
Card Background:           #101412
Elevated Card:             #171D18
Hover Surface:             #1C241E
Active Surface:            #202A22
Input Background:          #0C100E

BORDERS
Default Border:            #34372D
Subtle Border:             #252B26
Strong Border:             #4A4B3C

PRIMARY GREEN
Primary:                   #3FAF63
Primary Hover:             #52C978
Primary Active:            #328D50
Primary Bright:            #75F09A
Primary Dark:              #1E6B3A

GOLD
Gold:                      #C9A84E
Gold Hover:                #E0C16A
Gold Bright:               #F0D98A
Gold Dark:                 #92782F

AMBER
Amber:                     #D88932
Amber Hover:               #F0A94A
Amber Dark:                #92591F

TEXT
Primary Text:              #E9E8DF
Secondary Text:            #A5AAA1
Muted Text:                #6F766E
Disabled Text:             #4F554F
Inverse Text:              #071009

STATUS COLORS
Success:                   #45C46B
Success Background:        #102719

Warning:                   #D9A441
Warning Background:        #29200D

Error:                     #C94B45
Error Background:          #2A1110

Info:                      #68BFA0
Info Background:           #10231D


==================================================
2. COLOR USAGE RULES
==================================================

Use this approximate distribution:

70%  Black / charcoal backgrounds
20%  Dark green surfaces and accents
7%   Gold / brass
3%   Amber, red and other status colors

DO NOT make the entire interface green.

Green = primary interaction and system activity.
Gold = importance, premium elements, selected/high-value information.
Amber = warnings, timeline/system activity, attention.
Red = destructive actions and errors only.

The interface should remain predominantly dark.


==================================================
3. BACKGROUND SYSTEM
==================================================

App background:

#080A09

Main content background:

#0B0F0D

Sidebar:

#0A0E0C

Cards:

#101412

Modals:

#111713

Dropdowns:

#151B17

Use subtle tonal differences instead of obvious boxes everywhere.


==================================================
4. GRADIENT SYSTEM
==================================================

Do NOT use bright or excessive gradients.

Primary atmospheric gradient:

linear-gradient(
  135deg,
  #101412 0%,
  #0B100D 55%,
  #15130B 100%
)

Green atmospheric gradient:

linear-gradient(
  135deg,
  rgba(63,175,99,0.12),
  rgba(63,175,99,0.02)
)

Gold atmospheric gradient:

linear-gradient(
  135deg,
  rgba(201,168,78,0.10),
  rgba(201,168,78,0.02)
)

Premium gradient:

linear-gradient(
  135deg,
  rgba(63,175,99,0.10),
  rgba(201,168,78,0.07)
)


==================================================
5. BUTTON SYSTEM
==================================================

PRIMARY BUTTON

Background:
#3FAF63

Text:
#071009

Hover:
#52C978

Active:
#328D50

Border:
transparent

Shadow:
0 0 20px rgba(63,175,99,0.10)


SECONDARY BUTTON

Background:
transparent

Text:
#D8BB67

Border:
#C9A84E

Hover Background:
rgba(201,168,78,0.08)

Hover Border:
#E0C16A


GHOST BUTTON

Background:
transparent

Text:
#A5AAA1

Hover Background:
#171D18

Hover Text:
#E9E8DF


DANGER BUTTON

Background:
#C94B45

Text:
#FFF5F3

Hover:
#DF5B54


==================================================
6. INPUT SYSTEM
==================================================

Normal Input:

Background:
#0C100E

Border:
#34372D

Text:
#E9E8DF

Placeholder:
#6F766E


Hover:

Border:
#4A4B3C


Focus:

Border:
#3FAF63

Focus Ring:
rgba(63,175,99,0.18)

Focus Shadow:
0 0 0 3px rgba(63,175,99,0.08)


Error:

Border:
#C94B45

Focus Ring:
rgba(201,75,69,0.15)


==================================================
7. CARD SYSTEM
==================================================

DEFAULT CARD

Background:
#101412

Border:
1px solid #252B26

Border Radius:
12px

Shadow:
0 8px 30px rgba(0,0,0,0.25)


HOVER CARD

Background:
#171D18

Border:
#34372D

Transform:
translateY(-1px)

Transition:
150ms ease


IMPORTANT CARD

Use a subtle green/gold atmospheric gradient.

Border:
#34372D

Do NOT use bright glowing borders by default.


==================================================
8. NAVIGATION
==================================================

Sidebar Background:
#0A0E0C

Sidebar Border:
#252B26

Normal Navigation Text:
#A5AAA1

Hover Background:
#171D18

Hover Text:
#E9E8DF

Active Background:
rgba(63,175,99,0.10)

Active Text:
#75F09A

Active Indicator:
#3FAF63

Active Indicator Width:
3px


==================================================
9. TYPOGRAPHY
==================================================

Overall typography should feel:

- Modern
- Clean
- Technical
- Premium
- Slightly industrial

Primary Text:
#E9E8DF

Secondary:
#A5AAA1

Muted:
#6F766E

Headings:
#E9E8DF

Important headings may use:
#F0D98A

Do NOT use gold for every heading.

Recommended hierarchy:

H1:
32-40px
Weight: 700

H2:
24-30px
Weight: 700

H3:
18-22px
Weight: 600

Body:
14-16px
Weight: 400

Small:
12-13px

Labels:
11-13px
Weight: 600
Letter spacing: 0.04em


==================================================
10. ICON SYSTEM
==================================================

Icons should be simple, geometric and minimal.

Normal:
#A5AAA1

Hover:
#E9E8DF

Active:
#75F09A

Important:
#D8BB67

Do NOT use colorful icons unless they represent status.


==================================================
11. BADGES
==================================================

SUCCESS

Background:
#102719

Text:
#45C46B

Border:
rgba(69,196,107,0.25)


WARNING

Background:
#29200D

Text:
#D9A441

Border:
rgba(217,164,65,0.25)


ERROR

Background:
#2A1110

Text:
#C94B45

Border:
rgba(201,75,69,0.25)


PREMIUM

Background:
rgba(201,168,78,0.10)

Text:
#E0C16A

Border:
rgba(201,168,78,0.25)


==================================================
12. TABLES
==================================================

Table Background:
#101412

Header Background:
#151B17

Header Text:
#A5AAA1

Body Text:
#E9E8DF

Row Border:
#252B26

Hover Row:
#171D18

Selected Row:
rgba(63,175,99,0.08)

Do NOT use zebra striping unless necessary.


==================================================
13. MODALS / DIALOGS
==================================================

Overlay:
rgba(0,0,0,0.70)

Modal:
#111713

Border:
#34372D

Shadow:
0 25px 80px rgba(0,0,0,0.55)

Title:
#E9E8DF

Secondary:
#A5AAA1


==================================================
14. TOASTS / NOTIFICATIONS
==================================================

Success:
Background #102719
Border #45C46B
Text #E9E8DF

Warning:
Background #29200D
Border #D9A441
Text #E9E8DF

Error:
Background #2A1110
Border #C94B45
Text #E9E8DF

Info:
Background #10231D
Border #68BFA0
Text #E9E8DF


==================================================
15. GLOW SYSTEM
==================================================

Glow must be subtle.

GREEN:

box-shadow:
0 0 24px rgba(63,175,99,0.12);


GOLD:

box-shadow:
0 0 20px rgba(201,168,78,0.10);


AMBER:

box-shadow:
0 0 20px rgba(216,137,50,0.10);


Never use huge neon glows.

The UI should feel premium and cinematic, NOT like a gaming RGB dashboard.


==================================================
16. SPECIAL VISUAL LANGUAGE
==================================================

Use subtle visual references to:

- TVA machinery
- Timeline systems
- Analog/digital instrumentation
- Aged brass
- Emerald energy
- Industrial panels
- Retro-futuristic technology
- Dark metallic surfaces
- Subtle geometric patterns
- Thin technical lines
- Controlled glow
- Vintage institutional design

Do NOT directly reproduce Marvel/Loki assets.

Avoid:

- Loki character imagery
- Marvel logo
- TVA logo copied directly
- Movie screenshots
- Copyrighted symbols
- Excessive green
- Excessive gold
- Neon cyberpunk styling
- Generic glassmorphism
- Purple gradients
- Blue SaaS styling
- Rainbow gradients


==================================================
17. DECORATIVE ELEMENTS
==================================================

Decorative elements should be extremely subtle.

Allowed:

- Thin timeline lines
- Small grid patterns
- Technical corner markers
- Fine brass lines
- Circular system indicators
- Small green energy indicators
- Geometric borders
- Subtle radial gradients

Example background pattern:

radial-gradient(
  circle at 20% 20%,
  rgba(63,175,99,0.05),
  transparent 30%
)

Keep opacity extremely low.


==================================================
18. BORDER RADIUS
==================================================

Use restrained rounding.

Buttons:
8px

Inputs:
8px

Cards:
12px

Large containers:
16px

Modals:
16px

Do NOT make everything pill-shaped.

Pills are reserved for:

- Status
- Tags
- Filters
- Small metadata


==================================================
19. SHADOW SYSTEM
==================================================

Small:

0 2px 8px rgba(0,0,0,0.20)

Medium:

0 8px 30px rgba(0,0,0,0.25)

Large:

0 20px 60px rgba(0,0,0,0.40)

Modal:

0 25px 80px rgba(0,0,0,0.55)


==================================================
20. INTERACTION PRINCIPLES
==================================================

Every interactive element must clearly communicate:

DEFAULT
↓
HOVER
↓
FOCUS
↓
ACTIVE
↓
DISABLED
↓
ERROR/SUCCESS where applicable

Transitions should normally be:

120-180ms ease

Avoid excessive animations.

Use animation only when it improves:

- System feedback
- Loading
- State changes
- Navigation
- Important actions


==================================================
21. LOADING STATES
==================================================

Use dark skeletons with subtle movement.

Skeleton:
#171D18

Highlight:
#202A22

Progress indicators:
Primary Green #3FAF63

Important system processing:
Amber #D88932

Do NOT use bright white loading animations.


==================================================
22. DATA VISUALIZATION
==================================================

Primary data:
#3FAF63

Secondary:
#C9A84E

Third:
#68BFA0

Warning:
#D9A441

Error:
#C94B45

Grid:
#252B26

Axis:
#4A4B3C

Labels:
#A5AAA1

Charts must remain readable against #080A09.

Never use random colors just to make charts colorful.


==================================================
23. DESIGN PRINCIPLE
==================================================

The interface should communicate:

"An advanced system operating inside an old, mysterious institutional machine."

It should feel:

Dark
Premium
Controlled
Technical
Mysterious
Powerful
Industrial
Elegant

It should NOT feel:

Gamer
Comic-book
Neon
Overdesigned
Cyberpunk
Cheap
Generic SaaS


==================================================
24. MASTER TOKEN SET
==================================================

--bg-primary: #080A09;
--bg-secondary: #0B0F0D;
--bg-tertiary: #101412;

--surface: #101412;
--surface-elevated: #171D18;
--surface-hover: #1C241E;
--surface-active: #202A22;

--border-subtle: #252B26;
--border-default: #34372D;
--border-strong: #4A4B3C;

--primary: #3FAF63;
--primary-hover: #52C978;
--primary-active: #328D50;
--primary-bright: #75F09A;
--primary-dark: #1E6B3A;

--gold: #C9A84E;
--gold-hover: #E0C16A;
--gold-bright: #F0D98A;
--gold-dark: #92782F;

--amber: #D88932;
--amber-hover: #F0A94A;
--amber-dark: #92591F;

--text-primary: #E9E8DF;
--text-secondary: #A5AAA1;
--text-muted: #6F766E;
--text-disabled: #4F554F;
--text-inverse: #071009;

--success: #45C46B;
--warning: #D9A441;
--error: #C94B45;
--info: #68BFA0;


==================================================
25. FINAL IMPLEMENTATION RULE
==================================================

Apply this theme consistently across the ENTIRE software.

Do not invent random colors.

If a new component needs a color, derive it from the existing palette.

Prioritize accessibility and readability over visual effects.

Maintain strong contrast.

Use green and gold as controlled accents, not dominant backgrounds.

The final product should immediately feel like a sophisticated dark TVA-inspired software system while remaining completely usable as a professional application.