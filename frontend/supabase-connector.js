// ============================================================
// APUMAMART — Supabase Connector
// Website + Android App ka common backend
// ============================================================

const SUPABASE_URL = 'https://pyvjqmgzwymutbjwtoxg.supabase.co';
const SUPABASE_KEY = 'sb_publishable_ifcx8U2n-fRuRe1Z_Ew12w_IW37cEGe';

// Supabase client (via CDN: https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2)
// Usage: const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

const SupaDB = {
  client: null,

  init() {
    if (window.supabase) {
      this.client = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
      console.log('✅ Supabase connected');
      return true;
    }
    console.error('❌ Supabase JS not loaded. Add: <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>');
    return false;
  },

  // ---- PRODUCTS ----
  async getProducts(userId) {
    const { data, error } = await this.client
      .from('products').select('*').eq('user_id', userId);
    if (error) throw error;
    return data || [];
  },

  async addProduct(userId, product) {
    const { data, error } = await this.client
      .from('products').insert({ user_id: userId, ...product }).select();
    if (error) throw error;
    return data[0];
  },

  // ---- BILLS ----
  async getBills(userId) {
    const { data, error } = await this.client
      .from('bills').select('*').eq('user_id', userId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  },

  async addBill(userId, bill) {
    const { data, error } = await this.client
      .from('bills').insert({ user_id: userId, ...bill }).select();
    if (error) throw error;
    return data[0];
  },

  // ---- CUSTOMERS ----
  async getCustomers(userId) {
    const { data, error } = await this.client
      .from('customers').select('*').eq('user_id', userId);
    if (error) throw error;
    return data || [];
  },

  // ---- SUPPLIERS ----
  async getSuppliers(userId) {
    const { data, error } = await this.client
      .from('suppliers').select('*').eq('user_id', userId);
    if (error) throw error;
    return data || [];
  },

  // ---- EXPENSES ----
  async getExpenses(userId) {
    const { data, error } = await this.client
      .from('expenses').select('*').eq('user_id', userId)
      .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  },

  async addExpense(userId, expense) {
    const { data, error } = await this.client
      .from('expenses').insert({ user_id: userId, ...expense }).select();
    if (error) throw error;
    return data[0];
  }
};

// Auto-init when DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => SupaDB.init());
} else {
  SupaDB.init();
}
