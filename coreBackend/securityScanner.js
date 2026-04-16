// Import necessary modules
import { SecurityScanner } from './modules/SecurityScanner';
import { TestModule } from './modules/TestModule';

// Security scanner initialization
const scanner = new SecurityScanner();

// Run tests
const results = scanner.runAllTests();

// Logging results
console.log(results);