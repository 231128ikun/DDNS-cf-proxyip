import { render } from 'preact';
import { AuthGate } from './auth-gate';
import './styles.css';

const root = document.getElementById('app');
if (!root) throw new Error('missing #app root');

root.replaceChildren();
render(<AuthGate />, root);
