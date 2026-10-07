document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('menu-toggle-btn');
    const menu = document.getElementById('dropdown-menu');

    if (!toggle || !menu) return;

    toggle.setAttribute('aria-controls', menu.id);
    toggle.setAttribute('aria-expanded', 'false');
    menu.setAttribute('aria-hidden', 'true');

    const setMenuOpen = isOpen => {
        menu.classList.toggle('show', isOpen);
        toggle.classList.toggle('active', isOpen);
        toggle.setAttribute('aria-expanded', String(isOpen));
        menu.setAttribute('aria-hidden', String(!isOpen));
    };

    toggle.addEventListener('click', () => {
        setMenuOpen(toggle.getAttribute('aria-expanded') !== 'true');
    });

    document.addEventListener('click', event => {
        if (!menu.contains(event.target) && !toggle.contains(event.target)) {
            setMenuOpen(false);
        }
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape' && toggle.getAttribute('aria-expanded') === 'true') {
            setMenuOpen(false);
            toggle.focus();
        }
    });

    menu.addEventListener('click', event => {
        if (event.target.closest('a')) setMenuOpen(false);
    });
});