import { render } from 'preact';
import { App } from './app';
import './styles.css';

const root = document.getElementById('app');
if (!root) throw new Error('missing #app root');

render(<App />, root);