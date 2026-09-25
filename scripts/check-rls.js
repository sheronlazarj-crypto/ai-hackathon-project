// scripts/check-rls.js
require('dotenv').config({ path: '.env.local' });
const { createClient } = require('@supabase/supabase-js');
const Groq = require('groq-sdk');

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

async function explainRisk(tableName) {
  const prompt = `You are a security reviewer. In 2-3 short sentences, explain why a Supabase table with Row Level Security disabled is dangerous, using the table name "${tableName}" as the example. Be direct and practical.`;

  const response = await groq.chat.completions.create({
    model: 'openai/gpt-oss-120b',
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 150,
  });

  return response.choices[0].message.content.trim();
}

async function main() {
  console.log('🔍 Checking Supabase tables for disabled RLS...\n');

  const { data, error } = await supabase.rpc('get_rls_status');

  if (error) {
    console.log('⚠️ Error checking RLS:', error.message);
    return;
  }

  if (!data || data.length === 0) {
    console.log('ℹ️ No tables found in your database yet.');
    return;
  }

  const unsafeTables = data.filter((t) => !t.rls_enabled);

  if (unsafeTables.length === 0) {
    console.log('✅ All tables have Row Level Security enabled.');
    return;
  }

  console.log(`🚨 Found ${unsafeTables.length} table(s) with RLS disabled:\n`);

  for (const t of unsafeTables) {
    console.log(`  Table: ${t.table_name}`);
    console.log('  🤖 Analyzing with Groq...');
    const explanation = await explainRisk(t.table_name);
    console.log(`  Explanation: ${explanation}\n`);
  }
}

main();