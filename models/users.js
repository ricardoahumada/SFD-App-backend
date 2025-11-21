// In-memory user database
const users = [
  {
    id: 1,
    name: "Admin User",
    email: "admin@example.com",
    password: "admin123",
    role: "admin"
  },
  {
    id: 2,
    name: "Customer User",
    email: "customer@example.com",
    password: "customer123",
    role: "customer"
  }
];

/**
 * Find user by email
 * @param {string} email - User email
 * @returns {object|null} - User object or null if not found
 */
function findUserByEmail(email) {
  return users.find(user => user.email === email);
}

/**
 * Find user by ID
 * @param {number} id - User ID
 * @returns {object|null} - User object or null if not found
 */
function findUserById(id) {
  return users.find(user => user.id === id);
}

module.exports = {
  users,
  findUserByEmail,
  findUserById
};